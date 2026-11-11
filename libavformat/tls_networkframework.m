/*
 * Apple Network.framework TLS/DTLS backend
 * Copyright (c) 2026 gnattu
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with FFmpeg; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * Network.framework owns the TCP/UDP + TLS stack, unlike OpenSSL/GnuTLS which
 * layer TLS on an existing URLContext socket. Consequently:
 * - external_sock / ff_tls_set_external_socket are unsupported
 * - url_get_file_handle / url_get_short_seek return ENOSYS
 * - DTLS-SRTP key export is unsupported (no public API)
 */

#include <errno.h>

#include "avformat.h"
#include "avio_internal.h"
#include "internal.h"
#include "network.h"
#include "os_support.h"
#include "url.h"
#include "tls.h"
#include "libavutil/avstring.h"
#include "libavutil/getenv_utf8.h"
#include "libavutil/mem.h"
#include "libavutil/opt.h"
#include "libavutil/parseutils.h"
#include "libavutil/thread.h"
#include "libavutil/time.h"

#include <time.h>
#include <Network/Network.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dispatch/dispatch.h>

SecIdentityRef SecIdentityCreate(CFAllocatorRef allocator, SecCertificateRef certificate, SecKeyRef privateKey);

typedef struct TLSContext {
    TLSShared tls_shared;
    AVMutex lock;
    int lock_initialized;
    int closing;
    nw_listener_t listener;
    nw_connection_t connection;
    dispatch_queue_t queue;
    dispatch_semaphore_t listener_sem;
    dispatch_semaphore_t ready_sem;
    dispatch_semaphore_t recv_sem;
    dispatch_semaphore_t send_sem;
    dispatch_data_t recv_data;
    size_t recv_offset;
    bool recv_complete;
    int connected;
    int errored;
    int eof;
    int lastErr;
    int handshake_done;
    uintptr_t conn_generation;
    CFArrayRef ca_array;
    sec_identity_t local_identity;
    SecKeyRef private_key; /* retain for self-signed lifetime */
} TLSContext;

static int tls_init_lock(TLSContext *c)
{
    int ret;

    if (c->lock_initialized)
        return 0;

    ret = ff_mutex_init(&c->lock, NULL);
    if (ret)
        return AVERROR(ret);

    c->lock_initialized = 1;
    return 0;
}

static void tls_abort_connection(TLSContext *c)
{
    nw_connection_t connection = NULL;
    dispatch_semaphore_t ready_sem = NULL;
    dispatch_semaphore_t listener_sem = NULL;
    dispatch_semaphore_t recv_sem = NULL;
    dispatch_semaphore_t send_sem = NULL;

    ff_mutex_lock(&c->lock);
    c->closing = 1;
    c->errored = 1;
    c->lastErr = AVERROR_EXIT;
    connection = c->connection;
    ready_sem = c->ready_sem;
    listener_sem = c->listener_sem;
    recv_sem = c->recv_sem;
    send_sem = c->send_sem;
    if (connection)
        nw_retain(connection);
    if (ready_sem)
        dispatch_retain(ready_sem);
    if (listener_sem)
        dispatch_retain(listener_sem);
    if (recv_sem)
        dispatch_retain(recv_sem);
    if (send_sem)
        dispatch_retain(send_sem);
    ff_mutex_unlock(&c->lock);

    if (ready_sem)
        dispatch_semaphore_signal(ready_sem);
    if (listener_sem)
        dispatch_semaphore_signal(listener_sem);
    if (recv_sem)
        dispatch_semaphore_signal(recv_sem);
    if (send_sem)
        dispatch_semaphore_signal(send_sem);
    if (connection) {
        nw_connection_cancel(connection);
        nw_release(connection);
    }
    if (ready_sem)
        dispatch_release(ready_sem);
    if (listener_sem)
        dispatch_release(listener_sem);
    if (recv_sem)
        dispatch_release(recv_sem);
    if (send_sem)
        dispatch_release(send_sem);
}

static void log_nw_error(URLContext *h, const char *what, nw_error_t error)
{
    if (error) {
        av_log(h, AV_LOG_ERROR, "%s: domain=%d code=%d\n", what,
               (int)nw_error_get_error_domain(error),
               (int)nw_error_get_error_code(error));
    } else {
        av_log(h, AV_LOG_ERROR, "%s\n", what);
    }
}

static int wait_for_semaphore(URLContext *h, dispatch_semaphore_t sem)
{
    TLSContext *c = h->priv_data;

    while (1) {
        if (ff_check_interrupt(&h->interrupt_callback)) {
            tls_abort_connection(c);
            return AVERROR_EXIT;
        }
        if (dispatch_semaphore_wait(sem,
                dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC)) == 0)
            break;
    }

    if (ff_check_interrupt(&h->interrupt_callback)) {
        tls_abort_connection(c);
        return AVERROR_EXIT;
    }

    return 0;
}

static int import_pem_data(URLContext *h, const uint8_t *buf, size_t size,
                           const char *name, CFArrayRef *array)
{
#if !HAVE_SECITEMIMPORT
    return AVERROR_PATCHWELCOME;
#else
    CFDataRef data = NULL;
    CFStringRef nameStr = NULL;
    SecExternalFormat format = kSecFormatPEMSequence;
    SecExternalItemType type = kSecItemTypeAggregate;
    int ret = 0;

    *array = NULL;
    if (!buf || !size)
        return AVERROR(EINVAL);

    nameStr = CFStringCreateWithCString(NULL, name ? name : "pem",
                                        kCFStringEncodingUTF8);
    if (!nameStr)
        return AVERROR(ENOMEM);

    data = CFDataCreate(kCFAllocatorDefault, buf, (CFIndex)size);
    if (!data) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    if (SecItemImport(data, nameStr, &format, &type, 0, NULL, NULL, array) != noErr ||
        !*array) {
        ret = AVERROR_UNKNOWN;
        goto end;
    }

    if (CFArrayGetCount(*array) == 0) {
        CFRelease(*array);
        *array = NULL;
        ret = AVERROR_INVALIDDATA;
    }

end:
    if (nameStr)
        CFRelease(nameStr);
    if (data)
        CFRelease(data);
    return ret;
#endif
}

static int import_pem(URLContext *h, const char *path, CFArrayRef *array)
{
#if !HAVE_SECITEMIMPORT
    return AVERROR_PATCHWELCOME;
#else
    AVIOContext *s = NULL;
    int64_t size;
    unsigned char *buf = NULL;
    int ret;

    *array = NULL;
    ret = ffio_open_whitelist(&s, path, AVIO_FLAG_READ,
                              &h->interrupt_callback, NULL,
                              h->protocol_whitelist, h->protocol_blacklist);
    if (ret < 0)
        return ret;

    size = avio_size(s);
    if (size < 0) {
        ret = size;
        goto end;
    }
    if (size == 0) {
        ret = AVERROR_INVALIDDATA;
        goto end;
    }

    buf = av_malloc(size);
    if (!buf) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    ret = avio_read(s, buf, (int)size);
    if (ret < 0)
        goto end;

    ret = import_pem_data(h, buf, ret, path, array);

end:
    av_free(buf);
    if (s)
        avio_close(s);
    return ret;
#endif
}

/* Minimal DER helpers for EC P-256 self-signed certificates. */
static size_t der_len_size(size_t len)
{
    if (len < 0x80)
        return 1;
    if (len <= 0xff)
        return 2;
    return 3;
}

static uint8_t *der_put_len(uint8_t *p, size_t len)
{
    if (len < 0x80) {
        *p++ = (uint8_t)len;
    } else if (len <= 0xff) {
        *p++ = 0x81;
        *p++ = (uint8_t)len;
    } else {
        *p++ = 0x82;
        *p++ = (uint8_t)(len >> 8);
        *p++ = (uint8_t)len;
    }
    return p;
}

static uint8_t *der_put_tag_len(uint8_t *p, uint8_t tag, size_t len)
{
    *p++ = tag;
    return der_put_len(p, len);
}

static int gen_self_signed_identity(URLContext *h, TLSContext *c)
{
    SecKeyRef priv = NULL, pub = NULL;
    SecCertificateRef cert = NULL;
    SecIdentityRef identity = NULL;
    CFMutableDictionaryRef key_attrs = NULL;
    CFDataRef pub_data = NULL, sig = NULL, cert_data = NULL;
    CFErrorRef err = NULL;
    uint8_t *tbs = NULL, *cert_der = NULL, *spki = NULL;
    size_t tbs_size = 0, tbs_cap = 0, cert_size = 0, cert_cap = 0, spki_size = 0;
    const uint8_t *pub_bytes;
    size_t pub_len;
    int ret = 0;
    uint8_t *p;
    size_t serial_len, cn_len, subject_len, validity_len, spki_inner;
    /* CN=lavf */
    static const uint8_t cn_oid[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };
    static const uint8_t ec_oid[] = {
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01
    };
    static const uint8_t p256_oid[] = {
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
    };
    static const uint8_t ecdsa_sha256_oid[] = {
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
    };
    static const char *cn = "lavf";
    time_t t0 = time(NULL);
    time_t t1 = t0 + 365 * 24 * 3600;
    struct tm *tm0, *tm1;
    char not_before[16], not_after[16];

    tm0 = gmtime(&t0);
    if (!tm0) {
        ret = AVERROR_EXTERNAL;
        goto fail;
    }
    snprintf(not_before, sizeof(not_before), "%02d%02d%02d%02d%02d%02dZ",
             tm0->tm_year % 100, tm0->tm_mon + 1, tm0->tm_mday,
             tm0->tm_hour, tm0->tm_min, tm0->tm_sec);
    tm1 = gmtime(&t1);
    if (!tm1) {
        ret = AVERROR_EXTERNAL;
        goto fail;
    }
    snprintf(not_after, sizeof(not_after), "%02d%02d%02d%02d%02d%02dZ",
             tm1->tm_year % 100, tm1->tm_mon + 1, tm1->tm_mday,
             tm1->tm_hour, tm1->tm_min, tm1->tm_sec);

    key_attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                          &kCFTypeDictionaryKeyCallBacks,
                                          &kCFTypeDictionaryValueCallBacks);
    if (!key_attrs) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }
    CFDictionarySetValue(key_attrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    {
        int bits = 256;
        CFNumberRef n = CFNumberCreate(NULL, kCFNumberIntType, &bits);
        CFDictionarySetValue(key_attrs, kSecAttrKeySizeInBits, n);
        CFRelease(n);
    }
    CFDictionarySetValue(key_attrs, kSecAttrIsPermanent, kCFBooleanFalse);

    priv = SecKeyCreateRandomKey(key_attrs, &err);
    if (!priv) {
        av_log(h, AV_LOG_ERROR, "SecKeyCreateRandomKey failed\n");
        ret = AVERROR_EXTERNAL;
        goto fail;
    }
    pub = SecKeyCopyPublicKey(priv);
    if (!pub) {
        ret = AVERROR_EXTERNAL;
        goto fail;
    }
    pub_data = SecKeyCopyExternalRepresentation(pub, &err);
    if (!pub_data) {
        ret = AVERROR_EXTERNAL;
        goto fail;
    }
    pub_bytes = CFDataGetBytePtr(pub_data);
    pub_len = CFDataGetLength(pub_data);
    if (pub_len < 65 || pub_bytes[0] != 0x04) {
        ret = AVERROR_EXTERNAL;
        goto fail;
    }

    /* SubjectPublicKeyInfo */
    spki_inner = sizeof(ec_oid) + sizeof(p256_oid);
    spki_size = 1 + der_len_size(spki_inner) + spki_inner +
                1 + der_len_size(1 + pub_len) + 1 + pub_len;
    spki = av_malloc(2 + der_len_size(spki_size) + spki_size);
    if (!spki) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }
    p = spki;
    p = der_put_tag_len(p, 0x30, spki_size);
    p = der_put_tag_len(p, 0x30, spki_inner);
    memcpy(p, ec_oid, sizeof(ec_oid)); p += sizeof(ec_oid);
    memcpy(p, p256_oid, sizeof(p256_oid)); p += sizeof(p256_oid);
    p = der_put_tag_len(p, 0x03, 1 + pub_len);
    *p++ = 0x00;
    memcpy(p, pub_bytes, pub_len); p += pub_len;
    spki_size = p - spki;

    /* subject: RDN CN=lavf */
    cn_len = strlen(cn);
    subject_len = 1 + der_len_size(sizeof(cn_oid) + 1 + der_len_size(cn_len) + cn_len) +
                  sizeof(cn_oid) + 1 + der_len_size(cn_len) + cn_len;
    /* serial: 1 byte */
    serial_len = 1 + der_len_size(1) + 1;
    validity_len = 2 * (1 + der_len_size(13) + 13);

    /* Build TBSCertificate contents into tmp then wrap */
    {
        size_t alg_len = sizeof(ecdsa_sha256_oid);
        size_t version_len = 3; /* [0] EXPLICIT INTEGER 2 */
        size_t tbs_content =
            version_len + serial_len + alg_len +
            (1 + der_len_size(subject_len) + subject_len) + /* issuer */
            (1 + der_len_size(validity_len) + validity_len) +
            (1 + der_len_size(subject_len) + subject_len) + /* subject */
            spki_size;
        size_t off = 0;
        uint8_t *b;

        tbs_cap = 4 + tbs_content;
        tbs = av_malloc(tbs_cap);
        if (!tbs) {
            ret = AVERROR(ENOMEM);
            goto fail;
        }
        b = tbs;
        b = der_put_tag_len(b, 0x30, tbs_content);
        /* version v3 */
        *b++ = 0xa0; *b++ = 0x03; *b++ = 0x02; *b++ = 0x01; *b++ = 0x02;
        /* serialNumber */
        *b++ = 0x02; *b++ = 0x01; *b++ = 0x01;
        /* signature algorithm */
        memcpy(b, ecdsa_sha256_oid, alg_len); b += alg_len;
        /* issuer */
        b = der_put_tag_len(b, 0x30, subject_len);
        b = der_put_tag_len(b, 0x31, sizeof(cn_oid) + 1 + der_len_size(cn_len) + cn_len);
        b = der_put_tag_len(b, 0x30, sizeof(cn_oid) + 1 + der_len_size(cn_len) + cn_len);
        memcpy(b, cn_oid, sizeof(cn_oid)); b += sizeof(cn_oid);
        b = der_put_tag_len(b, 0x0c, cn_len); /* UTF8String */
        memcpy(b, cn, cn_len); b += cn_len;
        /* validity */
        b = der_put_tag_len(b, 0x30, validity_len);
        b = der_put_tag_len(b, 0x17, 13);
        memcpy(b, not_before, 13); b += 13;
        b = der_put_tag_len(b, 0x17, 13);
        memcpy(b, not_after, 13); b += 13;
        /* subject */
        b = der_put_tag_len(b, 0x30, subject_len);
        b = der_put_tag_len(b, 0x31, sizeof(cn_oid) + 1 + der_len_size(cn_len) + cn_len);
        b = der_put_tag_len(b, 0x30, sizeof(cn_oid) + 1 + der_len_size(cn_len) + cn_len);
        memcpy(b, cn_oid, sizeof(cn_oid)); b += sizeof(cn_oid);
        b = der_put_tag_len(b, 0x0c, cn_len);
        memcpy(b, cn, cn_len); b += cn_len;
        /* spki */
        memcpy(b, spki, spki_size); b += spki_size;
        tbs_size = b - tbs;
        (void)off;
    }

    {
        CFDataRef tbs_data = CFDataCreate(NULL, tbs, (CFIndex)tbs_size);
        if (!tbs_data) {
            ret = AVERROR(ENOMEM);
            goto fail;
        }
        sig = SecKeyCreateSignature(priv, kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                                    tbs_data, &err);
        CFRelease(tbs_data);
        if (!sig) {
            av_log(h, AV_LOG_ERROR, "SecKeyCreateSignature failed\n");
            ret = AVERROR_EXTERNAL;
            goto fail;
        }
    }

    {
        size_t sig_len = CFDataGetLength(sig);
        const uint8_t *sig_bytes = CFDataGetBytePtr(sig);
        size_t bitstring_len = 1 + sig_len;
        size_t total = tbs_size + sizeof(ecdsa_sha256_oid) +
                       1 + der_len_size(bitstring_len) + bitstring_len;
        uint8_t *b;

        cert_cap = 4 + total;
        cert_der = av_malloc(cert_cap);
        if (!cert_der) {
            ret = AVERROR(ENOMEM);
            goto fail;
        }
        b = cert_der;
        b = der_put_tag_len(b, 0x30, total);
        memcpy(b, tbs, tbs_size); b += tbs_size;
        memcpy(b, ecdsa_sha256_oid, sizeof(ecdsa_sha256_oid)); b += sizeof(ecdsa_sha256_oid);
        b = der_put_tag_len(b, 0x03, bitstring_len);
        *b++ = 0x00;
        memcpy(b, sig_bytes, sig_len); b += sig_len;
        cert_size = b - cert_der;
    }

    cert_data = CFDataCreate(NULL, cert_der, (CFIndex)cert_size);
    if (!cert_data) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }
    cert = SecCertificateCreateWithData(NULL, cert_data);
    if (!cert) {
        av_log(h, AV_LOG_ERROR, "SecCertificateCreateWithData failed\n");
        ret = AVERROR_EXTERNAL;
        goto fail;
    }

    identity = SecIdentityCreate(kCFAllocatorDefault, cert, priv);
    if (!identity) {
        av_log(h, AV_LOG_ERROR, "SecIdentityCreate failed\n");
        ret = AVERROR_EXTERNAL;
        goto fail;
    }

    c->local_identity = sec_identity_create(identity);
    if (!c->local_identity) {
        ret = AVERROR_EXTERNAL;
        goto fail;
    }
    c->private_key = priv;
    priv = NULL; /* owned by context for lifetime */

    av_log(h, AV_LOG_VERBOSE, "Generated self-signed certificate for TLS listen\n");
    ret = 0;

fail:
    av_free(tbs);
    av_free(cert_der);
    av_free(spki);
    if (key_attrs)
        CFRelease(key_attrs);
    if (pub_data)
        CFRelease(pub_data);
    if (sig)
        CFRelease(sig);
    if (cert_data)
        CFRelease(cert_data);
    if (cert)
        CFRelease(cert);
    if (identity)
        CFRelease(identity);
    if (pub)
        CFRelease(pub);
    if (priv)
        CFRelease(priv);
    if (err)
        CFRelease(err);
    return ret;
}

static int load_identity(URLContext *h, TLSContext *c)
{
    TLSShared *s = &c->tls_shared;
    CFArrayRef cert_array = NULL, key_array = NULL;
    SecIdentityRef identity = NULL;
    int ret = 0;

    if (s->cert_file && s->key_file) {
        ret = import_pem(h, s->cert_file, &cert_array);
        if (ret < 0)
            return ret;
        ret = import_pem(h, s->key_file, &key_array);
        if (ret < 0)
            goto fail;
    } else if (s->cert_buf && s->key_buf) {
        ret = import_pem_data(h, (const uint8_t *)s->cert_buf, strlen(s->cert_buf),
                              "cert.pem", &cert_array);
        if (ret < 0)
            return ret;
        ret = import_pem_data(h, (const uint8_t *)s->key_buf, strlen(s->key_buf),
                              "key.pem", &key_array);
        if (ret < 0)
            goto fail;
    } else if (s->listen) {
        av_log(h, AV_LOG_VERBOSE, "No server certificate provided, using self-signed\n");
        return gen_self_signed_identity(h, c);
    } else if (s->cert_file || s->key_file || s->cert_buf || s->key_buf) {
        av_log(h, AV_LOG_ERROR, "Both certificate and key are required\n");
        return AVERROR(EINVAL);
    } else {
        return 0;
    }

    identity = SecIdentityCreate(kCFAllocatorDefault,
                                 (SecCertificateRef)CFArrayGetValueAtIndex(cert_array, 0),
                                 (SecKeyRef)CFArrayGetValueAtIndex(key_array, 0));
    if (!identity) {
        ret = AVERROR(EINVAL);
        goto fail;
    }
    c->local_identity = sec_identity_create_with_certificates(identity, cert_array);
    if (!c->local_identity)
        ret = AVERROR(EINVAL);

fail:
    if (identity)
        CFRelease(identity);
    if (cert_array)
        CFRelease(cert_array);
    if (key_array)
        CFRelease(key_array);
    return ret;
}

static void configure_tls_options(sec_protocol_options_t sopts,
                                  TLSShared *s, TLSContext *c)
{
    if (s->is_dtls) {
        sec_protocol_options_set_min_tls_protocol_version(sopts,
            tls_protocol_version_DTLSv12);
    } else {
        /* Allow TLS 1.2+ including 1.3 (system max). */
        sec_protocol_options_set_min_tls_protocol_version(sopts,
            tls_protocol_version_TLSv12);
    }

    if (s->listen)
        sec_protocol_options_set_peer_authentication_required(sopts, s->verify);

    if (!s->verify) {
        sec_protocol_options_set_verify_block(sopts,
            ^(sec_protocol_metadata_t meta, sec_trust_t trust,
              sec_protocol_verify_complete_t complete) {
                complete(true);
            }, c->queue);
    } else if (c->ca_array) {
        sec_protocol_options_set_verify_block(sopts,
            ^(sec_protocol_metadata_t meta, sec_trust_t trust,
              sec_protocol_verify_complete_t complete) {
                SecTrustRef t = sec_trust_copy_ref(trust);
                bool trusted = false;
                if (t) {
                    SecTrustSetAnchorCertificates(t, c->ca_array);
                    SecTrustSetAnchorCertificatesOnly(t, true);
                    trusted = SecTrustEvaluateWithError(t, NULL);
                    CFRelease(t);
                }
                complete(trusted);
            }, c->queue);
    }

    if (c->local_identity)
        sec_protocol_options_set_local_identity(sopts, c->local_identity);

    /* SNI must not be a numeric literal (RFC 6066). */
    if (!s->listen && s->host && s->host[0] && !s->numerichost)
        sec_protocol_options_set_tls_server_name(sopts, s->host);
}

static void install_connection_state_handler(URLContext *h, TLSContext *c)
{
    uintptr_t gen = ++c->conn_generation;

    nw_connection_set_state_changed_handler(c->connection,
        ^(nw_connection_state_t state, nw_error_t error) {
            dispatch_semaphore_t state_ready_sem = NULL;

            ff_mutex_lock(&c->lock);
            if (c->conn_generation != gen)
                goto end;
            state_ready_sem = c->ready_sem;
            if (state_ready_sem)
                dispatch_retain(state_ready_sem);
            switch (state) {
            case nw_connection_state_ready:
                c->connected = 1;
                c->handshake_done = 1;
                break;
            case nw_connection_state_failed:
                if (!(c->closing && c->lastErr == AVERROR_EXIT)) {
                    c->errored = 1;
                    c->lastErr = AVERROR(EIO);
                    log_nw_error(h,
                                 c->tls_shared.listen ? "TLS server connection failed"
                                                      : "TLS connection failed",
                                 error);
                }
                break;
            case nw_connection_state_cancelled:
                if (c->connected)
                    c->eof = 1;
                break;
            case nw_connection_state_waiting:
            case nw_connection_state_preparing:
            case nw_connection_state_invalid:
            default:
                break;
            }
end:
            ff_mutex_unlock(&c->lock);
            if (state_ready_sem) {
                if (state == nw_connection_state_ready ||
                    state == nw_connection_state_failed)
                    dispatch_semaphore_signal(state_ready_sem);
                dispatch_release(state_ready_sem);
            }
            /* Wake any blocked read waiting for peer close. */
            if (state == nw_connection_state_failed ||
                state == nw_connection_state_cancelled) {
                dispatch_semaphore_t rs;
                ff_mutex_lock(&c->lock);
                rs = c->recv_sem;
                if (rs)
                    dispatch_retain(rs);
                ff_mutex_unlock(&c->lock);
                if (rs) {
                    dispatch_semaphore_signal(rs);
                    dispatch_release(rs);
                }
            }
        });
}

static int setup_proxy(URLContext *h, TLSContext *c, const char *host,
                       nw_privacy_context_t *privacy_ctx_out)
{
    TLSShared *s = &c->tls_shared;
    char *env_http_proxy = NULL;
    char *env_no_proxy = NULL;
    const char *proxy_url;
    int is_socks = 0, use_proxy = 0;
    nw_privacy_context_t privacy_ctx = NULL;

    *privacy_ctx_out = NULL;

    if (@available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)) {
        env_http_proxy = getenv_utf8("http_proxy");
        env_no_proxy = getenv_utf8("no_proxy");
        proxy_url = s->http_proxy ? s->http_proxy : env_http_proxy;

        if (proxy_url) {
            if (av_strstart(proxy_url, "http://", NULL))
                use_proxy = 1;
            else if (av_strstart(proxy_url, "socks5://", NULL) ||
                     av_strstart(proxy_url, "socks://", NULL)) {
                use_proxy = 1;
                is_socks = 1;
            }
        }
        if (env_no_proxy && use_proxy)
            use_proxy = !ff_http_match_no_proxy(env_no_proxy, host);

        if (use_proxy) {
            char proxy_host[200], proxy_auth[200], proxy_proto[16];
            char proxy_port_str[16];
            int proxy_port;
            nw_endpoint_t proxy_ep;
            nw_proxy_config_t proxy_cfg;

            av_url_split(proxy_proto, sizeof(proxy_proto),
                         proxy_auth, sizeof(proxy_auth),
                         proxy_host, sizeof(proxy_host), &proxy_port,
                         NULL, 0, proxy_url);
            if (proxy_port <= 0)
                proxy_port = is_socks ? 1080 : 80;

            snprintf(proxy_port_str, sizeof(proxy_port_str), "%d", proxy_port);
            proxy_ep = nw_endpoint_create_host(proxy_host, proxy_port_str);
            if (!proxy_ep) {
                freeenv_utf8(env_no_proxy);
                freeenv_utf8(env_http_proxy);
                return AVERROR(ENOMEM);
            }
            proxy_cfg = is_socks
                ? nw_proxy_config_create_socksv5(proxy_ep)
                : nw_proxy_config_create_http_connect(proxy_ep, NULL);
            nw_release(proxy_ep);
            if (proxy_auth[0]) {
                char *colon = strchr(proxy_auth, ':');
                if (colon) {
                    *colon = '\0';
                    nw_proxy_config_set_username_and_password(proxy_cfg,
                                                              proxy_auth, colon + 1);
                } else {
                    nw_proxy_config_set_username_and_password(proxy_cfg,
                                                              proxy_auth, "");
                }
            }
            privacy_ctx = nw_privacy_context_create("org.ffmpeg.tls");
            nw_privacy_context_add_proxy(privacy_ctx, proxy_cfg);
            nw_release(proxy_cfg);
            *privacy_ctx_out = privacy_ctx;
        }
        freeenv_utf8(env_no_proxy);
        freeenv_utf8(env_http_proxy);
    } else {
        char *env_proxy = getenv_utf8("http_proxy");
        if (s->http_proxy || env_proxy)
            av_log(h, AV_LOG_WARNING,
                   "http_proxy requires macOS 14 / iOS 17 or later with Network.framework\n");
        freeenv_utf8(env_proxy);
    }

    return 0;
}

static int tls_close(URLContext *h)
{
    TLSContext *c = h->priv_data;
    nw_listener_t listener = NULL;
    nw_connection_t connection = NULL;
    dispatch_queue_t queue = NULL;
    dispatch_data_t recv_data = NULL;
    dispatch_semaphore_t ready_sem = NULL;
    dispatch_semaphore_t listener_sem = NULL;
    dispatch_semaphore_t recv_sem = NULL;
    dispatch_semaphore_t send_sem = NULL;

    if (c->lock_initialized)
        ff_mutex_lock(&c->lock);

    c->closing = 1;
    if (!c->connected && !c->errored) {
        c->errored = 1;
        c->lastErr = AVERROR_EXIT;
    }
    c->errored = 1;
    if (!c->lastErr)
        c->lastErr = AVERROR_EXIT;

    listener = c->listener;
    connection = c->connection;
    queue = c->queue;
    recv_data = c->recv_data;
    ready_sem = c->ready_sem;
    listener_sem = c->listener_sem;
    recv_sem = c->recv_sem;
    send_sem = c->send_sem;

    c->listener = NULL;
    c->connection = NULL;
    c->queue = NULL;
    c->recv_data = NULL;
    c->ready_sem = NULL;
    c->listener_sem = NULL;
    c->recv_sem = NULL;
    c->send_sem = NULL;
    c->recv_offset = 0;
    c->recv_complete = false;

    if (ready_sem)
        dispatch_retain(ready_sem);
    if (listener_sem)
        dispatch_retain(listener_sem);
    if (recv_sem)
        dispatch_retain(recv_sem);
    if (send_sem)
        dispatch_retain(send_sem);

    if (c->lock_initialized)
        ff_mutex_unlock(&c->lock);

    if (ready_sem)
        dispatch_semaphore_signal(ready_sem);
    if (listener_sem)
        dispatch_semaphore_signal(listener_sem);
    if (recv_sem)
        dispatch_semaphore_signal(recv_sem);
    if (send_sem)
        dispatch_semaphore_signal(send_sem);

    if (listener)
        nw_listener_cancel(listener);
    if (connection)
        nw_connection_cancel(connection);
    if (queue)
        dispatch_barrier_sync(queue, ^{});

    if (listener)
        nw_release(listener);
    if (connection)
        nw_release(connection);
    if (queue)
        dispatch_release(queue);
    if (recv_data)
        dispatch_release(recv_data);

    /* original ownership + temporary retain */
    if (ready_sem) {
        dispatch_release(ready_sem);
        dispatch_release(ready_sem);
    }
    if (listener_sem) {
        dispatch_release(listener_sem);
        dispatch_release(listener_sem);
    }
    if (recv_sem) {
        dispatch_release(recv_sem);
        dispatch_release(recv_sem);
    }
    if (send_sem) {
        dispatch_release(send_sem);
        dispatch_release(send_sem);
    }
    if (c->ca_array) {
        CFRelease(c->ca_array);
        c->ca_array = NULL;
    }
    if (c->local_identity) {
        sec_release(c->local_identity);
        c->local_identity = NULL;
    }
    if (c->private_key) {
        CFRelease(c->private_key);
        c->private_key = NULL;
    }
    return 0;
}

static int process_buffered_data(uint8_t *buf, int size, TLSContext *c)
{
    const void *data_buf = NULL;
    size_t data_len = 0;
    dispatch_data_t recv_data = NULL;
    dispatch_data_t map;
    size_t avail, to_copy;

    ff_mutex_lock(&c->lock);
    recv_data = c->recv_data;
    if (recv_data)
        dispatch_retain(recv_data);
    ff_mutex_unlock(&c->lock);

    if (!recv_data)
        return -1;

    map = dispatch_data_create_map(recv_data, &data_buf, &data_len);
    if (!map || !data_buf) {
        dispatch_release(recv_data);
        if (map)
            dispatch_release(map);
        return -1;
    }

    ff_mutex_lock(&c->lock);
    if (c->recv_data != recv_data) {
        ff_mutex_unlock(&c->lock);
        dispatch_release(map);
        dispatch_release(recv_data);
        return -1;
    }
    avail = data_len - c->recv_offset;
    to_copy = avail > (size_t)size ? (size_t)size : avail;
    memcpy(buf, (const uint8_t *)data_buf + c->recv_offset, to_copy);
    dispatch_release(map);
    if (c->recv_offset + to_copy >= data_len) {
        dispatch_release(c->recv_data);
        c->recv_data = NULL;
        c->recv_offset = 0;
        /* For stream TLS, is_complete marks the current receive unit, not EOF. */
    } else {
        c->recv_offset += to_copy;
    }
    ff_mutex_unlock(&c->lock);
    dispatch_release(recv_data);
    return (int)to_copy;
}

static int tls_open(URLContext *h, const char *uri, int flags, AVDictionary **options)
{
    TLSContext *c = h->priv_data;
    TLSShared *s = &c->tls_shared;
    int ret;
    char host[200], port_str[16];
    int port;
    nw_parameters_t parameters = NULL;
    nw_privacy_context_t privacy_ctx = NULL;
    dispatch_semaphore_t listener_sem = NULL;
    dispatch_semaphore_t ready_sem = NULL;

    if (s->external_sock) {
        av_log(h, AV_LOG_ERROR,
               "Network.framework TLS backend does not support external_sock\n");
        return AVERROR_PATCHWELCOME;
    }

    ret = tls_init_lock(c);
    if (ret < 0)
        return ret;

    {
        const char *p = strchr(uri, '?');
        if (p) {
            ret = ff_parse_opts_from_query_string(s, p, 1);
            if (ret < 0)
                return ret;
        }
    }

    if (s->use_srtp) {
        av_log(h, AV_LOG_ERROR,
               "DTLS-SRTP is not supported by the Network.framework backend\n");
        return AVERROR_PATCHWELCOME;
    }

    ff_mutex_lock(&c->lock);
    if (c->closing) {
        ff_mutex_unlock(&c->lock);
        return c->lastErr ? c->lastErr : AVERROR_EXIT;
    }
    c->connected = c->errored = c->eof = c->lastErr = c->handshake_done = 0;
    if (c->recv_data) {
        dispatch_release(c->recv_data);
        c->recv_data = NULL;
    }
    c->recv_offset = 0;
    c->recv_complete = false;
    ff_mutex_unlock(&c->lock);

    av_url_split(NULL, 0, NULL, 0, host, sizeof(host), &port, NULL, 0, uri);
    if (!host[0] && !s->listen) {
        ret = AVERROR(EINVAL);
        goto fail;
    }
    if (port <= 0)
        port = 443;

    if (host[0]) {
        ret = ff_tls_parse_host(s, host, sizeof(host), &port, uri);
        if (ret < 0)
            goto fail;
        if (port <= 0)
            port = 443;
        av_strlcpy(host, s->host, sizeof(host));
    }

    c->queue = dispatch_queue_create("org.ffmpeg.tls.nw", DISPATCH_QUEUE_SERIAL);
    if (!c->queue) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }
    c->listener_sem = dispatch_semaphore_create(0);
    c->ready_sem = dispatch_semaphore_create(0);
    c->recv_sem = dispatch_semaphore_create(0);
    c->send_sem = dispatch_semaphore_create(0);
    listener_sem = c->listener_sem;
    ready_sem = c->ready_sem;
    if (listener_sem)
        dispatch_retain(listener_sem);
    if (ready_sem)
        dispatch_retain(ready_sem);

    if (s->ca_file) {
        ret = import_pem(h, s->ca_file, &c->ca_array);
        if (ret < 0)
            goto fail;
    }

    ret = load_identity(h, c);
    if (ret < 0)
        goto fail;

    if (!s->listen) {
        ret = setup_proxy(h, c, host, &privacy_ctx);
        if (ret < 0)
            goto fail;
    }

    snprintf(port_str, sizeof(port_str), "%d", port > 0 ? port : 0);

    if (s->is_dtls) {
        parameters = nw_parameters_create_secure_udp(
            ^(nw_protocol_options_t opts) {
                configure_tls_options(nw_tls_copy_sec_protocol_options(opts), s, c);
            },
            NW_PARAMETERS_DEFAULT_CONFIGURATION);
    } else {
        parameters = nw_parameters_create_secure_tcp(
            ^(nw_protocol_options_t opts) {
                configure_tls_options(nw_tls_copy_sec_protocol_options(opts), s, c);
            },
            NW_PARAMETERS_DEFAULT_CONFIGURATION);
    }
    if (!parameters) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    if (privacy_ctx) {
        nw_parameters_set_privacy_context(parameters, privacy_ctx);
        nw_release(privacy_ctx);
        privacy_ctx = NULL;
    }

    if (s->mtu > 0 && s->is_dtls) {
        /* Best-effort: Network.framework has no direct DTLS MTU setter like OpenSSL. */
        av_log(h, AV_LOG_VERBOSE, "DTLS mtu=%d (application write clamp only)\n", s->mtu);
    }

    if (s->listen) {
        if (host[0]) {
            nw_endpoint_t local_endpoint = nw_endpoint_create_host(host, port_str);
            if (!local_endpoint) {
                ret = AVERROR(ENOMEM);
                goto fail;
            }
            nw_parameters_set_local_endpoint(parameters, local_endpoint);
            nw_release(local_endpoint);
            c->listener = nw_listener_create(parameters);
        } else {
            c->listener = nw_listener_create_with_port(port_str, parameters);
        }
        nw_release(parameters);
        parameters = NULL;
        if (!c->listener) {
            av_log(h, AV_LOG_ERROR, "Unable to create nw_listener\n");
            ret = AVERROR(ENOMEM);
            goto fail;
        }

        nw_listener_set_queue(c->listener, c->queue);
        nw_listener_set_state_changed_handler(c->listener,
            ^(nw_listener_state_t state, nw_error_t error) {
                dispatch_semaphore_t state_listener_sem = NULL;
                dispatch_semaphore_t state_ready_sem = NULL;

                ff_mutex_lock(&c->lock);
                state_listener_sem = c->listener_sem;
                state_ready_sem = c->ready_sem;
                if (state_listener_sem)
                    dispatch_retain(state_listener_sem);
                if (state_ready_sem)
                    dispatch_retain(state_ready_sem);
                switch (state) {
                case nw_listener_state_ready:
                    break;
                case nw_listener_state_failed:
                    if (!(c->closing && c->lastErr == AVERROR_EXIT)) {
                        c->errored = 1;
                        c->lastErr = AVERROR(EIO);
                        log_nw_error(h, "TLS listener failed", error);
                    }
                    break;
                case nw_listener_state_cancelled:
                    if (!c->connected) {
                        c->errored = 1;
                        if (!c->lastErr)
                            c->lastErr = AVERROR(EIO);
                    }
                    break;
                default:
                    break;
                }
                ff_mutex_unlock(&c->lock);
                if (state_listener_sem) {
                    if (state != nw_listener_state_invalid)
                        dispatch_semaphore_signal(state_listener_sem);
                    dispatch_release(state_listener_sem);
                }
                if (state_ready_sem) {
                    if (state == nw_listener_state_failed ||
                        state == nw_listener_state_cancelled)
                        dispatch_semaphore_signal(state_ready_sem);
                    dispatch_release(state_ready_sem);
                }
            });
        nw_listener_set_new_connection_handler(c->listener,
            ^(nw_connection_t connection) {
                ff_mutex_lock(&c->lock);
                if (c->connection || c->errored || c->closing) {
                    ff_mutex_unlock(&c->lock);
                    nw_connection_cancel(connection);
                    return;
                }
                c->connection = nw_retain(connection);
                nw_connection_set_queue(c->connection, c->queue);
                install_connection_state_handler(h, c);
                nw_connection_start(c->connection);
                ff_mutex_unlock(&c->lock);
            });
        nw_listener_start(c->listener);

        ret = wait_for_semaphore(h, listener_sem);
        if (ret < 0)
            goto fail;
    } else {
        nw_endpoint_t endpoint = nw_endpoint_create_host(host, port_str);
        if (!endpoint) {
            ret = AVERROR(ENOMEM);
            goto fail;
        }
        c->connection = nw_connection_create(endpoint, parameters);
        nw_release(endpoint);
        nw_release(parameters);
        parameters = NULL;
        if (!c->connection) {
            av_log(h, AV_LOG_ERROR, "Unable to create nw_connection\n");
            ret = AVERROR(ENOMEM);
            goto fail;
        }
        nw_connection_set_queue(c->connection, c->queue);
        install_connection_state_handler(h, c);
        nw_connection_start(c->connection);
    }

    /* For DTLS with deferred handshake (url_handshake), do not block here. */
    if (s->is_dtls && (h->flags & AVIO_FLAG_NONBLOCK)) {
        dispatch_release(listener_sem);
        dispatch_release(ready_sem);
        return 0;
    }

    ret = wait_for_semaphore(h, ready_sem);
    if (ret < 0)
        goto fail;
    ff_mutex_lock(&c->lock);
    if (c->errored || !c->connected)
        ret = c->lastErr ? c->lastErr : AVERROR(EIO);
    ff_mutex_unlock(&c->lock);
    if (ret < 0)
        goto fail;

    dispatch_release(listener_sem);
    dispatch_release(ready_sem);
    return 0;

fail:
    if (listener_sem)
        dispatch_release(listener_sem);
    if (ready_sem)
        dispatch_release(ready_sem);
    if (parameters)
        nw_release(parameters);
    if (privacy_ctx)
        nw_release(privacy_ctx);
    tls_close(h);
    return ret;
}

static int dtls_handshake(URLContext *h)
{
    TLSContext *c = h->priv_data;
    dispatch_semaphore_t ready_sem;
    int ret;

    ff_mutex_lock(&c->lock);
    if (c->handshake_done && c->connected) {
        ff_mutex_unlock(&c->lock);
        return 0;
    }
    if (c->errored) {
        ret = c->lastErr ? c->lastErr : AVERROR(EIO);
        ff_mutex_unlock(&c->lock);
        return ret;
    }
    ready_sem = c->ready_sem;
    if (ready_sem)
        dispatch_retain(ready_sem);
    ff_mutex_unlock(&c->lock);

    if (!ready_sem)
        return AVERROR(EIO);

    if (h->flags & AVIO_FLAG_NONBLOCK) {
        if (dispatch_semaphore_wait(ready_sem, dispatch_time(DISPATCH_TIME_NOW, 0)) != 0) {
            dispatch_release(ready_sem);
            return AVERROR(EAGAIN);
        }
        dispatch_release(ready_sem);
        ff_mutex_lock(&c->lock);
        if (c->connected && c->handshake_done)
            ret = 0;
        else if (c->errored)
            ret = c->lastErr ? c->lastErr : AVERROR(EIO);
        else
            ret = AVERROR(EAGAIN);
        ff_mutex_unlock(&c->lock);
        return ret;
    }

    ret = wait_for_semaphore(h, ready_sem);
    dispatch_release(ready_sem);
    if (ret < 0)
        return ret;

    ff_mutex_lock(&c->lock);
    if (c->errored || !c->connected)
        ret = c->lastErr ? c->lastErr : AVERROR(EIO);
    else
        ret = 0;
    ff_mutex_unlock(&c->lock);
    return ret;
}

static int tls_read(URLContext *h, uint8_t *buf, int size)
{
    TLSContext *c = h->priv_data;
    nw_connection_t connection = NULL;
    dispatch_semaphore_t recv_sem = NULL;
    int ret = 0;
    int nonblock = h->flags & AVIO_FLAG_NONBLOCK;

    ff_mutex_lock(&c->lock);
    if (c->errored || c->closing) {
        ret = c->lastErr ? c->lastErr : AVERROR(EIO);
        ff_mutex_unlock(&c->lock);
        return ret;
    }
    if (c->eof) {
        ff_mutex_unlock(&c->lock);
        return AVERROR_EOF;
    }
    connection = c->connection;
    recv_sem = c->recv_sem;
    if (connection)
        nw_retain(connection);
    if (recv_sem)
        dispatch_retain(recv_sem);
    ff_mutex_unlock(&c->lock);

    if (!connection || !recv_sem) {
        if (connection)
            nw_release(connection);
        if (recv_sem)
            dispatch_release(recv_sem);
        return c->lastErr ? c->lastErr : AVERROR(EIO);
    }

    ff_mutex_lock(&c->lock);
    if (c->recv_data)
        ret = 1;
    else if (c->eof)
        ret = AVERROR_EOF;
    else
        ret = 0;
    ff_mutex_unlock(&c->lock);

    if (ret == 1) {
        ret = process_buffered_data(buf, size, c);
        if (ret >= 0)
            goto done;
    }
    if (ret == AVERROR_EOF)
        goto done;

    nw_connection_receive(connection, 1, (uint32_t)size,
        ^(dispatch_data_t content, nw_content_context_t ctx,
          bool is_complete, nw_error_t error) {
            dispatch_semaphore_t callback_recv_sem;

            ff_mutex_lock(&c->lock);
            if (error && !(c->closing && c->lastErr == AVERROR_EXIT)) {
                c->errored = 1;
                c->lastErr = AVERROR(EIO);
            }
            if (content) {
                if (c->recv_data)
                    dispatch_release(c->recv_data);
                dispatch_retain(content);
                c->recv_data = content;
                c->recv_offset = 0;
            }
            c->recv_complete = is_complete;
            if (is_complete && !content)
                c->eof = 1;
            callback_recv_sem = c->recv_sem;
            if (callback_recv_sem)
                dispatch_retain(callback_recv_sem);
            ff_mutex_unlock(&c->lock);
            if (callback_recv_sem) {
                dispatch_semaphore_signal(callback_recv_sem);
                dispatch_release(callback_recv_sem);
            }
        });

    if (nonblock) {
        if (dispatch_semaphore_wait(recv_sem, dispatch_time(DISPATCH_TIME_NOW, 0)) != 0) {
            ret = AVERROR(EAGAIN);
            goto done;
        }
    } else {
        while (1) {
            if (ff_check_interrupt(&h->interrupt_callback)) {
                tls_abort_connection(c);
                break;
            }
            if (dispatch_semaphore_wait(recv_sem,
                    dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC)) == 0)
                break;
        }
        if (ff_check_interrupt(&h->interrupt_callback)) {
            ret = AVERROR_EXIT;
            goto done;
        }
    }

    ff_mutex_lock(&c->lock);
    if (c->errored)
        ret = c->lastErr ? c->lastErr : AVERROR(EIO);
    else if (c->recv_data)
        ret = 1;
    else if (c->eof)
        ret = AVERROR_EOF;
    else
        ret = AVERROR(EAGAIN);
    ff_mutex_unlock(&c->lock);

    if (ret < 0 && ret != AVERROR_EOF)
        goto done;
    if (ret == 1) {
        ret = process_buffered_data(buf, size, c);
        if (ret >= 0)
            goto done;
        ret = AVERROR(EAGAIN);
    }

done:
    nw_release(connection);
    dispatch_release(recv_sem);
    return ret;
}

static int tls_write(URLContext *h, const uint8_t *buf, int size)
{
    TLSContext *c = h->priv_data;
    TLSShared *s = &c->tls_shared;
    nw_connection_t connection = NULL;
    dispatch_queue_t queue = NULL;
    dispatch_semaphore_t send_sem = NULL;
    __block int send_err = 0;
    int ret = 0;
    int nonblock = h->flags & AVIO_FLAG_NONBLOCK;

    if (s->is_dtls && s->mtu > 0)
        size = FFMIN(size, s->mtu);

    ff_mutex_lock(&c->lock);
    if (c->errored || c->closing) {
        ret = c->lastErr ? c->lastErr : AVERROR(EIO);
        ff_mutex_unlock(&c->lock);
        return ret;
    }
    connection = c->connection;
    queue = c->queue;
    send_sem = c->send_sem;
    if (connection)
        nw_retain(connection);
    if (queue)
        dispatch_retain(queue);
    if (send_sem)
        dispatch_retain(send_sem);
    ff_mutex_unlock(&c->lock);

    if (!connection || !queue || !send_sem) {
        if (connection)
            nw_release(connection);
        if (queue)
            dispatch_release(queue);
        if (send_sem)
            dispatch_release(send_sem);
        return c->lastErr ? c->lastErr : AVERROR(EIO);
    }

    if (size <= 0)
        goto done;

    {
        dispatch_data_t data = dispatch_data_create(buf, (size_t)size,
                                                    queue, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
        if (!data) {
            ret = AVERROR(ENOMEM);
            goto done;
        }
        nw_connection_send(connection, data, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true,
            ^(nw_error_t error) {
                dispatch_semaphore_t callback_send_sem;

                ff_mutex_lock(&c->lock);
                if (error && !(c->closing && c->lastErr == AVERROR_EXIT)) {
                    c->errored = 1;
                    c->lastErr = AVERROR(EIO);
                    send_err = -1;
                }
                callback_send_sem = c->send_sem;
                if (callback_send_sem)
                    dispatch_retain(callback_send_sem);
                ff_mutex_unlock(&c->lock);
                if (callback_send_sem) {
                    dispatch_semaphore_signal(callback_send_sem);
                    dispatch_release(callback_send_sem);
                }
            });
        dispatch_release(data);
    }

    if (nonblock) {
        if (dispatch_semaphore_wait(send_sem, dispatch_time(DISPATCH_TIME_NOW, 0)) != 0) {
            ret = AVERROR(EAGAIN);
            goto done;
        }
    } else {
        while (1) {
            if (ff_check_interrupt(&h->interrupt_callback)) {
                tls_abort_connection(c);
                break;
            }
            if (dispatch_semaphore_wait(send_sem,
                    dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC)) == 0)
                break;
        }
        if (ff_check_interrupt(&h->interrupt_callback)) {
            ret = AVERROR_EXIT;
            goto done;
        }
    }

    ff_mutex_lock(&c->lock);
    if (send_err || c->errored)
        ret = c->lastErr ? c->lastErr : AVERROR(EIO);
    ff_mutex_unlock(&c->lock);
    if (ret < 0)
        goto done;
    ret = size;

done:
    if (connection)
        nw_release(connection);
    if (queue)
        dispatch_release(queue);
    if (send_sem)
        dispatch_release(send_sem);
    return ret;
}

static int tls_get_file_handle(URLContext *h)
{
    return AVERROR(ENOSYS);
}

static int tls_get_short_seek(URLContext *h)
{
    return AVERROR(ENOSYS);
}

int ff_tls_set_external_socket(URLContext *h, URLContext *sock)
{
    av_log(h, AV_LOG_ERROR,
           "Network.framework TLS backend does not support external sockets\n");
    return AVERROR_PATCHWELCOME;
}

int ff_dtls_export_materials(URLContext *h, char *dtls_srtp_materials, size_t materials_sz)
{
    av_log(h, AV_LOG_ERROR,
           "DTLS-SRTP key export is not available with Network.framework\n");
    return AVERROR_PATCHWELCOME;
}

int ff_ssl_read_key_cert(char *key_url, char *cert_url,
                         char *key_buf, size_t key_sz,
                         char *cert_buf, size_t cert_sz,
                         char **fingerprint)
{
    return AVERROR_PATCHWELCOME;
}

int ff_ssl_gen_key_cert(char *key_buf, size_t key_sz,
                        char *cert_buf, size_t cert_sz,
                        char **fingerprint)
{
    return AVERROR_PATCHWELCOME;
}

static int dtls_open(URLContext *h, const char *uri, int flags, AVDictionary **options)
{
    TLSContext *c = h->priv_data;
    c->tls_shared.is_dtls = 1;
    return tls_open(h, uri, flags, options);
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
    .name                = "tls",
    .url_open2           = tls_open,
    .url_read            = tls_read,
    .url_write           = tls_write,
    .url_close           = tls_close,
    .url_get_file_handle = tls_get_file_handle,
    .url_get_short_seek  = tls_get_short_seek,
    .priv_data_size      = sizeof(TLSContext),
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .priv_data_class     = &tls_class,
};

static const AVClass dtls_class = {
    .class_name = "dtls",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};

const URLProtocol ff_dtls_protocol = {
    .name                = "dtls",
    .url_open2           = dtls_open,
    .url_handshake       = dtls_handshake,
    .url_read            = tls_read,
    .url_write           = tls_write,
    .url_close           = tls_close,
    .url_get_file_handle = tls_get_file_handle,
    .url_get_short_seek  = tls_get_short_seek,
    .priv_data_size      = sizeof(TLSContext),
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .priv_data_class     = &dtls_class,
};
