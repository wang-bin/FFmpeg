/*
 * TLS/SSL Protocol
 * Copyright (c) 2026
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "avformat.h"
#include "network.h"
#include "url.h"
#include "tls.h"

#include "libavutil/opt.h"

#include <openssl/pem.h>
#include <picotls.h>
#include <picotls/openssl.h>

typedef struct TLSContext {
    const AVClass *class;
    TLSShared tls_shared;

    ptls_context_t ptls_ctx;
    ptls_t *tls;

    ptls_openssl_verify_certificate_t verify_certificate;
    int verify_certificate_inited;

    ptls_openssl_sign_certificate_t sign_certificate;
    int sign_certificate_inited;

    ptls_buffer_t sendbuf;
    ptls_buffer_t recvbuf;
    int buffers_inited;
} TLSContext;

static void shift_buffer(ptls_buffer_t *buf, size_t delta)
{
    if (!delta)
        return;
    if (delta < buf->off)
        memmove(buf->base, buf->base + delta, buf->off - delta);
    buf->off -= delta;
}

static int log_ptls_error(URLContext *h, const char *where, int err)
{
    av_log(h, AV_LOG_ERROR, "picotls %s failed: %d\n", where, err);
    return AVERROR(EIO);
}

static int tls_flush_output(URLContext *h)
{
    TLSContext *s = h->priv_data;
    TLSShared *c = &s->tls_shared;

    while (s->sendbuf.off) {
        int ret = ffurl_write(c->tcp, s->sendbuf.base, s->sendbuf.off);
        if (ret < 0)
            return ret;
        if (!ret)
            return AVERROR(EIO);
        shift_buffer(&s->sendbuf, ret);
    }

    return 0;
}

static int tls_process_ciphertext(URLContext *h, const uint8_t *buf, size_t len)
{
    TLSContext *s = h->priv_data;
    size_t off = 0;

    while (off < len) {
        size_t inlen = len - off;
        int ret = ptls_receive(s->tls, &s->recvbuf, buf + off, &inlen);

        if (!inlen) {
            av_log(h, AV_LOG_ERROR, "picotls receive consumed no data\n");
            return AVERROR_INVALIDDATA;
        }

        off += inlen;

        if (ret == 0 || ret == PTLS_ERROR_IN_PROGRESS)
            continue;

        return log_ptls_error(h, "receive", ret);
    }

    return 0;
}

static int tls_run_handshake(URLContext *h)
{
    TLSContext *s = h->priv_data;
    TLSShared *c = &s->tls_shared;
    uint8_t buf[16384];

    while (!ptls_handshake_is_complete(s->tls)) {
        int ret = tls_flush_output(h);
        if (ret < 0)
            return ret;

        ret = ffurl_read(c->tcp, buf, sizeof(buf));
        if (ret < 0)
            return ret;
        if (!ret)
            return AVERROR_EOF;

        for (size_t off = 0; off < ret;) {
            size_t inlen = ret - off;
            int hsret = ptls_handshake(s->tls, &s->sendbuf, buf + off, &inlen, NULL);

            if (!inlen) {
                av_log(h, AV_LOG_ERROR, "picotls handshake consumed no data\n");
                return AVERROR_INVALIDDATA;
            }

            off += inlen;

            if (hsret == 0) {
                if (off < ret)
                    return tls_process_ciphertext(h, buf + off, ret - off);
                break;
            }
            if (hsret != PTLS_ERROR_IN_PROGRESS)
                return log_ptls_error(h, "handshake", hsret);
        }
    }

    return tls_flush_output(h);
}

static X509_STORE *tls_create_store(const char *ca_file)
{
    X509_STORE *store;
    X509_LOOKUP *lookup;

    store = X509_STORE_new();
    if (!store)
        return NULL;

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (!lookup || X509_LOOKUP_load_file(lookup, ca_file, X509_FILETYPE_PEM) != 1) {
        X509_STORE_free(store);
        return NULL;
    }

    return store;
}

static int tls_setup_certificate(TLSContext *s, URLContext *h)
{
    TLSShared *c = &s->tls_shared;
    FILE *fp = NULL;
    EVP_PKEY *pkey = NULL;
    int ret;

    if (!c->cert_file && !c->key_file)
        return 0;
    if (!c->cert_file || !c->key_file) {
        av_log(h, AV_LOG_ERROR, "Both cert_file and key_file are required for picotls\n");
        return AVERROR(EINVAL);
    }

    ret = ptls_load_certificates(&s->ptls_ctx, c->cert_file);
    if (ret)
        return log_ptls_error(h, "load certificates", ret);

    fp = fopen(c->key_file, "rb");
    if (!fp) {
        av_log(h, AV_LOG_ERROR, "Failed to open key file: %s\n", c->key_file);
        return AVERROR(errno);
    }

    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        av_log(h, AV_LOG_ERROR, "Failed to read private key: %s\n", c->key_file);
        return AVERROR(EIO);
    }

    ret = ptls_openssl_init_sign_certificate(&s->sign_certificate, pkey);
    EVP_PKEY_free(pkey);
    if (ret)
        return log_ptls_error(h, "init sign_certificate", ret);

    s->sign_certificate_inited = 1;
    s->ptls_ctx.sign_certificate = &s->sign_certificate.super;

    return 0;
}

static void tls_free_certificates(TLSContext *s)
{
    size_t i;
    for (i = 0; i < s->ptls_ctx.certificates.count; i++)
        free(s->ptls_ctx.certificates.list[i].base);
    free(s->ptls_ctx.certificates.list);
    s->ptls_ctx.certificates.list = NULL;
    s->ptls_ctx.certificates.count = 0;
}

static int tls_close(URLContext *h)
{
    TLSContext *s = h->priv_data;

    if (s->tls)
        ptls_free(s->tls);
    s->tls = NULL;

    if (s->verify_certificate_inited)
        ptls_openssl_dispose_verify_certificate(&s->verify_certificate);
    s->verify_certificate_inited = 0;

    if (s->sign_certificate_inited)
        ptls_openssl_dispose_sign_certificate(&s->sign_certificate);
    s->sign_certificate_inited = 0;

    tls_free_certificates(s);

    if (s->buffers_inited) {
        ptls_buffer_dispose(&s->sendbuf);
        ptls_buffer_dispose(&s->recvbuf);
    }
    s->buffers_inited = 0;

    ffurl_closep(&s->tls_shared.tcp);
    return 0;
}

static int tls_open(URLContext *h, const char *uri, int flags, AVDictionary **options)
{
    TLSContext *s = h->priv_data;
    TLSShared *c = &s->tls_shared;
    int ret;

    if ((ret = ff_tls_open_underlying(c, h, uri, options)) < 0)
        goto fail;

    ptls_buffer_init(&s->sendbuf, NULL, 0);
    ptls_buffer_init(&s->recvbuf, NULL, 0);
    s->buffers_inited = 1;

    memset(&s->ptls_ctx, 0, sizeof(s->ptls_ctx));
    s->ptls_ctx.random_bytes  = ptls_openssl_random_bytes;
    s->ptls_ctx.get_time      = &ptls_get_time;
    s->ptls_ctx.key_exchanges = ptls_openssl_key_exchanges;
    s->ptls_ctx.cipher_suites = ptls_openssl_cipher_suites;

    if ((ret = tls_setup_certificate(s, h)) < 0)
        goto fail;
    if (c->listen && !s->sign_certificate_inited) {
        av_log(h, AV_LOG_ERROR, "Listening mode requires cert_file and key_file for picotls\n");
        ret = AVERROR(EINVAL);
        goto fail;
    }

    if (!c->listen && c->verify) {
        X509_STORE *store = c->ca_file ? tls_create_store(c->ca_file) : NULL;
        if (c->ca_file && !store) {
            av_log(h, AV_LOG_ERROR, "Failed to load CA file: %s\n", c->ca_file);
            ret = AVERROR(EIO);
            goto fail;
        }
        ret = ptls_openssl_init_verify_certificate(&s->verify_certificate, store);
        if (ret) {
            ret = log_ptls_error(h, "init verify_certificate", ret);
            goto fail;
        }
        s->verify_certificate_inited = 1;
        s->ptls_ctx.verify_certificate = &s->verify_certificate.super;
    }

    s->tls = c->listen ? ptls_server_new(&s->ptls_ctx) : ptls_client_new(&s->ptls_ctx);
    if (!s->tls) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    if (!c->listen && c->host && !c->numerichost) {
        ret = ptls_set_server_name(s->tls, c->host, 0);
        if (ret) {
            ret = log_ptls_error(h, "set server_name", ret);
            goto fail;
        }
    }

    if (!c->listen) {
        ret = ptls_handshake(s->tls, &s->sendbuf, NULL, NULL, NULL);
        if (ret != 0 && ret != PTLS_ERROR_IN_PROGRESS) {
            ret = log_ptls_error(h, "start handshake", ret);
            goto fail;
        }
    }

    ret = tls_run_handshake(h);
    if (ret < 0)
        goto fail;

    return 0;

fail:
    tls_close(h);
    return ret;
}

static int tls_read(URLContext *h, uint8_t *buf, int size)
{
    TLSContext *s = h->priv_data;
    TLSShared *c = &s->tls_shared;

    if (!size)
        return 0;

    while (!s->recvbuf.off) {
        uint8_t inbuf[16384];
        int ret = ffurl_read(c->tcp, inbuf, sizeof(inbuf));
        if (ret < 0)
            return ret;
        if (!ret)
            return AVERROR_EOF;

        ret = tls_process_ciphertext(h, inbuf, ret);
        if (ret < 0)
            return ret;
    }

    size = FFMIN(size, s->recvbuf.off);
    memcpy(buf, s->recvbuf.base, size);
    shift_buffer(&s->recvbuf, size);
    return size;
}

static int tls_write(URLContext *h, const uint8_t *buf, int size)
{
    TLSContext *s = h->priv_data;
    int ret;

    ret = tls_flush_output(h);
    if (ret < 0)
        return ret;

    ret = ptls_send(s->tls, &s->sendbuf, buf, size);
    if (ret)
        return log_ptls_error(h, "send", ret);

    ret = tls_flush_output(h);
    if (ret < 0)
        return ret;

    return size;
}

static int tls_get_file_handle(URLContext *h)
{
    TLSContext *s = h->priv_data;
    return ffurl_get_file_handle(s->tls_shared.tcp);
}

static int tls_get_short_seek(URLContext *h)
{
    TLSContext *s = h->priv_data;
    return ffurl_get_short_seek(s->tls_shared.tcp);
}

static const AVOption options[] = {
    TLS_COMMON_OPTIONS(TLSContext, tls_shared),
    { NULL }
};

static const AVClass tls_class = {
    .class_name = "tls",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};

const URLProtocol ff_tls_protocol = {
    .name              = "tls",
    .url_open2         = tls_open,
    .url_read          = tls_read,
    .url_write         = tls_write,
    .url_close         = tls_close,
    .url_get_file_handle = tls_get_file_handle,
    .url_get_short_seek  = tls_get_short_seek,
    .priv_data_size    = sizeof(TLSContext),
    .flags             = URL_PROTOCOL_FLAG_NETWORK,
    .priv_data_class   = &tls_class,
};
