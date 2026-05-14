/*
 * lossless JPEG shared bits
 * Copyright (c) 2000, 2001 Fabrice Bellard
 * Copyright (c) 2003 Alex Beregszaszi
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

#include <stdint.h>
#include <string.h>

#include "libavutil/hdr_gainmap.h"
#include "libavutil/pixdesc.h"
#include "libavutil/pixfmt.h"

#include "avcodec.h"
#include "bytestream.h"
#include "idctdsp.h"
#include "jpegtables.h"
#include "put_bits.h"
#include "mjpegenc.h"
#include "mjpegenc_common.h"
#include "mjpeg.h"
#include "version.h"

/* table_class: 0 = DC coef, 1 = AC coefs */
static int put_huffman_table(PutBitContext *p, int table_class, int table_id,
                             const uint8_t *bits_table, const uint8_t *value_table)
{
    int n = 0;

    put_bits(p, 4, table_class);
    put_bits(p, 4, table_id);

    for (int i = 1; i <= 16; i++) {
        n += bits_table[i];
        put_bits(p, 8, bits_table[i]);
    }

    for (int i = 0; i < n; i++)
        put_bits(p, 8, value_table[i]);

    return n + 17;
}

static void jpeg_table_header(AVCodecContext *avctx, PutBitContext *p,
                              const MJpegContext *m,
                              const uint8_t intra_matrix_permutation[64],
                              const uint16_t luma_intra_matrix[64],
                              const uint16_t chroma_intra_matrix[64],
                              int hsample[3], int use_slices, int matrices_differ)
{
    int size;
    uint8_t *ptr;

    if (m) {
        int matrix_count = 1 + matrices_differ;
        if (m->force_duplicated_matrix)
            matrix_count = 2;
        /* quant matrixes */
        put_marker(p, DQT);
        put_bits(p, 16, 2 + matrix_count * (1 + 64));
        put_bits(p, 4, 0); /* 8 bit precision */
        put_bits(p, 4, 0); /* table 0 */
        for (int i = 0; i < 64; i++) {
            uint8_t j = intra_matrix_permutation[i];
            put_bits(p, 8, luma_intra_matrix[j]);
        }

        if (matrix_count > 1) {
            put_bits(p, 4, 0); /* 8 bit precision */
            put_bits(p, 4, 1); /* table 1 */
            for (int i = 0; i < 64; i++) {
                uint8_t j = intra_matrix_permutation[i];
                put_bits(p, 8, chroma_intra_matrix[j]);
            }
        }
    }

    if (use_slices) {
        put_marker(p, DRI);
        put_bits(p, 16, 4);
        put_bits(p, 16, (avctx->width-1)/(8*hsample[0]) + 1);
    }

    /* huffman table */
    put_marker(p, DHT);
    flush_put_bits(p);
    ptr = put_bits_ptr(p);
    put_bits(p, 16, 0); /* patched later */
    size = 2;

    // Only MJPEG can have a variable Huffman variable. All other
    // formats use the default Huffman table.
    if (m && m->huffman == HUFFMAN_TABLE_OPTIMAL) {
        size += put_huffman_table(p, 0, 0, m->bits_dc_luminance,
                                  m->val_dc_luminance);
        size += put_huffman_table(p, 0, 1, m->bits_dc_chrominance,
                                  m->val_dc_chrominance);

        size += put_huffman_table(p, 1, 0, m->bits_ac_luminance,
                                  m->val_ac_luminance);
        size += put_huffman_table(p, 1, 1, m->bits_ac_chrominance,
                                  m->val_ac_chrominance);
    } else {
        size += put_huffman_table(p, 0, 0, ff_mjpeg_bits_dc_luminance,
                                  ff_mjpeg_val_dc);
        size += put_huffman_table(p, 0, 1, ff_mjpeg_bits_dc_chrominance,
                                  ff_mjpeg_val_dc);

        size += put_huffman_table(p, 1, 0, ff_mjpeg_bits_ac_luminance,
                                  ff_mjpeg_val_ac_luminance);
        size += put_huffman_table(p, 1, 1, ff_mjpeg_bits_ac_chrominance,
                                  ff_mjpeg_val_ac_chrominance);
    }
    AV_WB16(ptr, size);
}

enum {
    ICC_HDR_SIZE    = 16, /* ICC_PROFILE\0 tag + 4 bytes */
    ICC_CHUNK_SIZE  = UINT16_MAX - ICC_HDR_SIZE,
    ICC_MAX_CHUNKS  = UINT8_MAX,
};

int ff_mjpeg_add_icc_profile_size(AVCodecContext *avctx, const AVFrame *frame,
                                  size_t *max_pkt_size)
{
    const AVFrameSideData *sd;
    size_t new_pkt_size;
    int nb_chunks;
    sd = av_frame_get_side_data(frame, AV_FRAME_DATA_ICC_PROFILE);
    if (!sd || !sd->size)
        return 0;

    if (sd->size > ICC_MAX_CHUNKS * ICC_CHUNK_SIZE) {
        av_log(avctx, AV_LOG_ERROR, "Cannot store %zu byte ICC "
               "profile: too large for JPEG\n",
               sd->size);
        return AVERROR_INVALIDDATA;
    }

    nb_chunks = (sd->size + ICC_CHUNK_SIZE - 1) / ICC_CHUNK_SIZE;
    new_pkt_size = *max_pkt_size + nb_chunks * (UINT16_MAX + 2 /* APP2 marker */);
    if (new_pkt_size < *max_pkt_size) /* overflow */
        return AVERROR_INVALIDDATA;
    *max_pkt_size = new_pkt_size;
    return 0;
}

int ff_mjpeg_add_gain_map_size(AVCodecContext *avctx, const AVFrame *frame,
                               size_t *max_pkt_size)
{
    const AVFrameSideData *sd;
    const AVHDRGainMap *gainmap;

    sd = av_frame_get_side_data(frame, AV_FRAME_DATA_HDR_GAINMAP);
    if (!sd || sd->size < sizeof(AVHDRGainMap))
        return 0;

    gainmap = (const AVHDRGainMap *)sd->data;

    /* Reserve space for metadata in primary JPEG and MPF overhead.
     * Over-reserve to cover either XMP or ISO. */
    /* XMP APP1 or ISO APP2 (version-only) in primary: ~700 bytes worst case */
    *max_pkt_size += 700;
    /* MPF APP2 in primary: 90 bytes */
    *max_pkt_size += 90; /* MPF_APP2_SIZE */
    /* Metadata injected into secondary JPEG (XMP or ISO): ~700 bytes worst case */
    *max_pkt_size += 700;

    /* If there is an embedded gain map frame, reserve space for its JPEG */
#define GAINMAP_FALLBACK_SIZE 131072
    if (gainmap->gain_map_frame) {
        /* Rough upper bound: width * height * 3 + some overhead */
        int w = gainmap->gain_map_frame->width;
        int h = gainmap->gain_map_frame->height;
        if (w > 0 && h > 0)
            *max_pkt_size += (size_t)w * h * 3 + 65536;
        else
            *max_pkt_size += GAINMAP_FALLBACK_SIZE;
    }
#undef GAINMAP_FALLBACK_SIZE

    return 0;
}

/**
 * Encode the ISO 21496-1 binary metadata payload (excluding APP2 marker and
 * namespace) into @p buf.  Returns the number of bytes written.
 *
 * Maximum payload size (3-channel case):
 *   5 (hdr: 2+2+1) + 16 (headrooms: 4×4) + 3×40 (10 fields × 4 bytes) = 141
 * We use 160 to leave a small safety margin.
 */
#define ISO_GAINMAP_PAYLOAD_MAX 160
static int write_iso_gainmap_payload(const AVHDRGainMap *gainmap,
                                     uint8_t *buf, int buf_size)
{
    /* ISO 21496-1 uses separate denominators (no common-denominator optimisation
     * here for simplicity).  Fields in the spec:
     *   uint16 minimum_version, writer_version
     *   uint8  flags  (bit 0: isMultiChannel, bit 2: backwardDirection)
     *   uint32 baseHdrHeadroomN/D, alternateHdrHeadroomN/D
     *   per channel (1 or 3×):
     *     int32/uint32 gainMapMin N/D, gainMapMax N/D, gainMapGamma N/D,
     *                  baseOffset N/D, alternateOffset N/D
     */
    int channelCount = 1;
    uint8_t flags = 0;
    PutByteContext pb;

    /* Determine if all three channels are identical */
    for (int c = 1; c < 3; c++) {
        if (gainmap->gain_map_min[c].num    != gainmap->gain_map_min[0].num    ||
            gainmap->gain_map_min[c].den    != gainmap->gain_map_min[0].den    ||
            gainmap->gain_map_max[c].num    != gainmap->gain_map_max[0].num    ||
            gainmap->gain_map_max[c].den    != gainmap->gain_map_max[0].den    ||
            gainmap->gamma[c].num           != gainmap->gamma[0].num           ||
            gainmap->gamma[c].den           != gainmap->gamma[0].den           ||
            gainmap->base_offset[c].num     != gainmap->base_offset[0].num     ||
            gainmap->base_offset[c].den     != gainmap->base_offset[0].den     ||
            gainmap->alternate_offset[c].num != gainmap->alternate_offset[0].num ||
            gainmap->alternate_offset[c].den != gainmap->alternate_offset[0].den) {
            channelCount = 3;
            break;
        }
    }

    if (channelCount == 3)
        flags |= 0x01; /* kIsMultiChannelMask */
    if (gainmap->base_rendition_is_hdr)
        flags |= 0x04; /* backwardDirection: base is HDR */

    /* Worst-case size: 2+2+1 header + 4*4 headrooms + 3*10*4 channel = 125 bytes */
    if (buf_size < ISO_GAINMAP_PAYLOAD_MAX)
        return 0;

    bytestream2_init_writer(&pb, buf, buf_size);

    bytestream2_put_be16u(&pb, 0);     /* minimum_version = 0 */
    bytestream2_put_be16u(&pb, 0);     /* writer_version = 0 */
    bytestream2_put_byteu(&pb, flags);

    /* base / alternate HDR headroom */
    bytestream2_put_be32u(&pb, (uint32_t)gainmap->base_hdr_headroom.num);
    bytestream2_put_be32u(&pb, (uint32_t)gainmap->base_hdr_headroom.den);
    bytestream2_put_be32u(&pb, (uint32_t)gainmap->alternate_hdr_headroom.num);
    bytestream2_put_be32u(&pb, (uint32_t)gainmap->alternate_hdr_headroom.den);

    for (int c = 0; c < channelCount; c++) {
        bytestream2_put_be32u(&pb, (uint32_t)gainmap->gain_map_min[c].num);
        bytestream2_put_be32u(&pb, (uint32_t)gainmap->gain_map_min[c].den);
        bytestream2_put_be32u(&pb, (uint32_t)gainmap->gain_map_max[c].num);
        bytestream2_put_be32u(&pb, (uint32_t)gainmap->gain_map_max[c].den);
        bytestream2_put_be32u(&pb, (uint32_t)gainmap->gamma[c].num);
        bytestream2_put_be32u(&pb, (uint32_t)gainmap->gamma[c].den);
        bytestream2_put_be32u(&pb, (uint32_t)gainmap->base_offset[c].num);
        bytestream2_put_be32u(&pb, (uint32_t)gainmap->base_offset[c].den);
        bytestream2_put_be32u(&pb, (uint32_t)gainmap->alternate_offset[c].num);
        bytestream2_put_be32u(&pb, (uint32_t)gainmap->alternate_offset[c].den);
    }

    return bytestream2_tell_p(&pb);
}

/**
 * Insert a JPEG APP segment immediately after the SOI marker.
 * @param pkt     JPEG packet to modify (must start with FF D8)
 * @param marker  APP marker byte (e.g. 0xE1 for APP1, 0xE2 for APP2)
 * @param data    segment payload (namespace + metadata); written as-is
 * @param size    length of @p data in bytes
 * @return 0 on success, negative AVERROR on failure
 */
static int inject_app_segment(AVPacket *pkt, uint8_t marker,
                               const uint8_t *data, int size)
{
    /* Full block: FF <marker>(2) + length(2) + data */
    int block_size = 2 + 2 + size;
    int old_size   = pkt->size;
    int ret        = av_grow_packet(pkt, block_size);
    if (ret < 0)
        return ret;
    memmove(pkt->data + 2 + block_size, pkt->data + 2, old_size - 2);
    pkt->data[2] = 0xFF;
    pkt->data[3] = marker;
    AV_WB16(pkt->data + 4, block_size - 2); /* length excl. marker */
    memcpy(pkt->data + 6, data, size);
    return 0;
}

/**
 * Inject a full ISO 21496-1 APP2 segment into a JPEG packet right after its
 * SOI marker.  Used to embed the complete gain map metadata into the secondary
 * (gain map) JPEG when encoding in ISO mode.
 */
int ff_mjpeg_inject_iso_app2(AVPacket *pkt, const AVHDRGainMap *gainmap)
{
    /* ISO namespace: "urn:iso:std:iso:ts:21496:-1\0" (28 bytes incl. NUL) */
    static const char iso_ns[] = "urn:iso:std:iso:ts:21496:-1";
    uint8_t seg[sizeof(iso_ns) + ISO_GAINMAP_PAYLOAD_MAX];
    int payload_len;

    if (!pkt || !gainmap)
        return AVERROR(EINVAL);
    if (pkt->size < 2 || pkt->data[0] != 0xFF || pkt->data[1] != 0xD8)
        return AVERROR_INVALIDDATA;

    memcpy(seg, iso_ns, sizeof(iso_ns));
    payload_len = write_iso_gainmap_payload(gainmap,
                                            seg + sizeof(iso_ns),
                                            ISO_GAINMAP_PAYLOAD_MAX);
    if (payload_len <= 0)
        return AVERROR(EINVAL);

    return inject_app_segment(pkt, 0xE2, seg, (int)sizeof(iso_ns) + payload_len);
}

/**
 * Inject an XMP APP1 gain-map metadata segment into a JPEG packet right after
 * its SOI marker.  Used to embed XMP metadata into the secondary (gain map)
 * JPEG when encoding in XMP mode.
 */
int ff_mjpeg_inject_xmp_app1(AVPacket *pkt, const AVHDRGainMap *gainmap)
{
    static const char xmp_ns[] = "http://ns.adobe.com/xap/1.0/";
    char xmp_body[512];
    uint8_t seg[sizeof(xmp_ns) + 512];
    int xmp_body_len;
    const char *base_is_hdr;

    if (!pkt || !gainmap)
        return AVERROR(EINVAL);
    if (pkt->size < 2 || pkt->data[0] != 0xFF || pkt->data[1] != 0xD8)
        return AVERROR_INVALIDDATA;

    base_is_hdr = gainmap->base_rendition_is_hdr ? "True" : "False";
    xmp_body_len = snprintf(xmp_body, sizeof(xmp_body),
        "<?xpacket begin=\"\xef\xbb\xbf\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>"
        "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">"
        "<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">"
        "<rdf:Description rdf:about=\"\""
        " xmlns:hdrgm=\"http://ns.adobe.com/hdr-gain-map/1.0/\""
        " hdrgm:Version=\"1.0\""
        " hdrgm:GainMapMin=\"%.8g\""
        " hdrgm:GainMapMax=\"%.8g\""
        " hdrgm:Gamma=\"%.8g\""
        " hdrgm:OffsetSDR=\"%.8g\""
        " hdrgm:OffsetHDR=\"%.8g\""
        " hdrgm:HDRCapacityMin=\"%.8g\""
        " hdrgm:HDRCapacityMax=\"%.8g\""
        " hdrgm:BaseRenditionIsHDR=\"%s\"/>"
        "</rdf:RDF></x:xmpmeta>"
        "<?xpacket end=\"w\"?>",
        av_q2d(gainmap->gain_map_min[0]),
        av_q2d(gainmap->gain_map_max[0]),
        av_q2d(gainmap->gamma[0]),
        av_q2d(gainmap->base_offset[0]),
        av_q2d(gainmap->alternate_offset[0]),
        av_q2d(gainmap->base_hdr_headroom),
        av_q2d(gainmap->alternate_hdr_headroom),
        base_is_hdr);

    if (xmp_body_len <= 0 || xmp_body_len >= (int)sizeof(xmp_body))
        return AVERROR(EINVAL);

    memcpy(seg, xmp_ns, sizeof(xmp_ns));
    memcpy(seg + sizeof(xmp_ns), xmp_body, xmp_body_len);
    return inject_app_segment(pkt, 0xE1, seg, (int)sizeof(xmp_ns) + xmp_body_len);
}

/**
 * Scan a JPEG buffer and return the byte offset of the SOS (0xFFDA) marker,
 * or -1 if not found.  Used to inject MPF right before SOS.
 */
static int find_sos_offset(const uint8_t *data, int size)
{
    GetByteContext gb;
    uint8_t marker;
    int seg_len;
    bytestream2_init(&gb, data, size);
    bytestream2_skipu(&gb, 2); /* skip SOI */
    while (bytestream2_get_bytes_left(&gb) >= 4) {
        if (bytestream2_peek_byteu(&gb) != 0xFF)
            return -1;
        bytestream2_skipu(&gb, 1);
        marker = bytestream2_get_byteu(&gb);
        if (marker == 0xDA) /* SOS */
            return (int)(gb.buffer - gb.buffer_start) - 2;
        if (marker == 0xD8 || marker == 0xD9) /* SOI/EOI */
            return -1;
        seg_len = bytestream2_get_be16u(&gb);
        if (seg_len < 2)
            return -1;
        bytestream2_skip(&gb, seg_len - 2);
    }
    return -1;
}

/*
 * MPF APP2 block layout (90 bytes total), matching libultrahdr:
 *   [0..1]   FF E2         APP2 marker
 *   [2..3]   00 58         length = 88 (excl. marker)
 *   [4..7]   MPF\0         MPF identifier
 *   [8..9]   MM            TIFF big-endian byte order
 *   [10..11] 00 2A         TIFF magic
 *   [12..15] 00 00 00 08   IFD0 offset from MM = 8
 *   [16..17] 00 03         3 IFD entries
 *   [18..29] B000 tag      version "0100"  (12 bytes)
 *   [30..41] B001 tag      number of images = 2  (12 bytes)
 *   [42..53] B002 tag      MP Entry, value-offset from MM = 50  (12 bytes)
 *   [54..57] 00 00 00 00   next IFD = 0
 *   [58..73] primary MP Entry   (16 bytes)
 *   [74..89] secondary MP Entry (16 bytes)
 *
 * The secondary image data offset is measured from the byte right after
 * the MPF\0 signature (i.e. MPF_marker_pos + 8) to the secondary SOI,
 * matching the libultrahdr reference implementation.
 */
#define MPF_APP2_SIZE 90

/**
 * Inject a Multi-Picture Format (MPF) APP2 segment into the primary JPEG
 * packet right before its SOS marker.  The MPF encodes the sizes and offsets
 * needed to locate the appended secondary (gain-map) JPEG.
 *
 * @param pkt            primary JPEG packet (modified in place)
 * @param secondary_size total byte size of the secondary JPEG (after any
 *                       metadata injection)
 * @return 0 on success, a negative AVERROR on failure
 */
int ff_mjpeg_inject_mpf(AVPacket *pkt, uint32_t secondary_size)
{
    uint8_t mpf[MPF_APP2_SIZE];
    PutByteContext pb;
    int ins_pos;
    uint32_t primary_after, sec_offset;
    int old_size, ret;

    if (!pkt || !pkt->data || pkt->size < 4 ||
        pkt->data[0] != 0xFF || pkt->data[1] != 0xD8)
        return AVERROR_INVALIDDATA;

    /* Insert MPF right before SOS so the order is: headers → MPF → SOS */
    ins_pos = find_sos_offset(pkt->data, pkt->size);
    if (ins_pos < 2)
        ins_pos = 2; /* fall back to right after SOI */

    /* After injection the primary grows by MPF_APP2_SIZE bytes.
     * primary_after = total size of the primary JPEG in the final stream. */
    primary_after = (uint32_t)(pkt->size + MPF_APP2_SIZE);

    /* Secondary image data offset, measured from the byte right after the
     * MPF\0 signature (ins_pos + 8) to the first byte of the secondary SOI,
     * following the libultrahdr reference implementation convention:
     *   offset = primary_after - (MPF_marker_pos + 8)
     * The MPF marker is at ins_pos in the final primary (it does not move
     * during injection — we shift what is AFTER ins_pos). */
    sec_offset = primary_after - (uint32_t)(ins_pos + 8);

    /* --- Build MPF block using PutByteContext ----------------------------- */
    bytestream2_init_writer(&pb, mpf, MPF_APP2_SIZE);

    bytestream2_put_be16u(&pb, 0xFFE2);               /* APP2 marker */
    bytestream2_put_be16u(&pb, MPF_APP2_SIZE - 2);    /* length = 88 */
    /* MPF identifier */
    bytestream2_put_byteu(&pb, 'M');
    bytestream2_put_byteu(&pb, 'P');
    bytestream2_put_byteu(&pb, 'F');
    bytestream2_put_byteu(&pb, '\0');
    /* TIFF big-endian header; IFD0 at TIFF offset 8 */
    bytestream2_put_be16u(&pb, 0x4D4D);               /* "MM" big-endian */
    bytestream2_put_be16u(&pb, 0x002A);               /* TIFF magic */
    bytestream2_put_be32u(&pb, 8);                    /* IFD0 offset from MM */
    /* IFD0 tag count */
    bytestream2_put_be16u(&pb, 3);
    /* Tag 0xB000: MPF Version = "0100" (4 UNDEFINED bytes, inline) */
    bytestream2_put_be16u(&pb, 0xB000);
    bytestream2_put_be16u(&pb, 7);                    /* type: UNDEFINED */
    bytestream2_put_be32u(&pb, 4);                    /* count */
    bytestream2_put_byteu(&pb, '0');
    bytestream2_put_byteu(&pb, '1');
    bytestream2_put_byteu(&pb, '0');
    bytestream2_put_byteu(&pb, '0');
    /* Tag 0xB001: Number of Images = 2 (1 LONG, inline) */
    bytestream2_put_be16u(&pb, 0xB001);
    bytestream2_put_be16u(&pb, 4);                    /* type: LONG */
    bytestream2_put_be32u(&pb, 1);                    /* count */
    bytestream2_put_be32u(&pb, 2);                    /* value: 2 images */
    /* Tag 0xB002: MP Entry (32 bytes, value offset from MM = 50) */
    bytestream2_put_be16u(&pb, 0xB002);
    bytestream2_put_be16u(&pb, 7);                    /* type: UNDEFINED */
    bytestream2_put_be32u(&pb, 32);                   /* count: 2 × 16 bytes */
    bytestream2_put_be32u(&pb, 50);                   /* value offset from MM */
    /* Next IFD offset = 0 */
    bytestream2_put_be32u(&pb, 0);
    /* Primary MP Entry (TIFF offset 50 from MM = mpf[8+50]) */
    bytestream2_put_be32u(&pb, 0x03000000);           /* attr: primary+representative+JPEG */
    bytestream2_put_be32u(&pb, primary_after);        /* individual image size */
    bytestream2_put_be32u(&pb, 0);                    /* data offset = 0 for primary */
    bytestream2_put_be16u(&pb, 0);                    /* dep image 1 = 0 */
    bytestream2_put_be16u(&pb, 0);                    /* dep image 2 = 0 */
    /* Secondary MP Entry */
    bytestream2_put_be32u(&pb, 0x00000000);           /* attr: supplementary JPEG */
    bytestream2_put_be32u(&pb, secondary_size);       /* individual image size */
    bytestream2_put_be32u(&pb, sec_offset);           /* data offset */
    bytestream2_put_be16u(&pb, 0);                    /* dep image 1 = 0 */
    bytestream2_put_be16u(&pb, 0);                    /* dep image 2 = 0 */

    /* --- Inject into packet ---------------------------------------------- */
    old_size = pkt->size;
    ret = av_grow_packet(pkt, MPF_APP2_SIZE);
    if (ret < 0)
        return ret;
    memmove(pkt->data + ins_pos + MPF_APP2_SIZE,
            pkt->data + ins_pos, old_size - ins_pos);
    memcpy(pkt->data + ins_pos, mpf, MPF_APP2_SIZE);
    return 0;
}

static void jpeg_put_comments(AVCodecContext *avctx, PutBitContext *p,
                              const AVFrame *frame,
                              const struct MJpegContext *m)
{
    const AVFrameSideData *sd = NULL;
    int size;
    uint8_t *ptr;

    if (avctx->sample_aspect_ratio.num > 0 && avctx->sample_aspect_ratio.den > 0) {
        AVRational sar = avctx->sample_aspect_ratio;

        if (sar.num > 65535 || sar.den > 65535) {
            if (!av_reduce(&sar.num, &sar.den, avctx->sample_aspect_ratio.num, avctx->sample_aspect_ratio.den, 65535))
                av_log(avctx, AV_LOG_WARNING,
                    "Cannot store exact aspect ratio %d:%d\n",
                    avctx->sample_aspect_ratio.num,
                    avctx->sample_aspect_ratio.den);
        }

        /* JFIF header */
        put_marker(p, APP0);
        put_bits(p, 16, 16);
        ff_put_string(p, "JFIF", 1); /* this puts the trailing zero-byte too */
        /* The most significant byte is used for major revisions, the least
         * significant byte for minor revisions. Version 1.02 is the current
         * released revision. */
        put_bits(p, 16, 0x0102);
        put_bits(p,  8, 0);              /* units type: 0 - aspect ratio */
        put_bits(p, 16, sar.num);
        put_bits(p, 16, sar.den);
        put_bits(p, 8, 0); /* thumbnail width */
        put_bits(p, 8, 0); /* thumbnail height */
    }

    /* ICC profile */
    sd = av_frame_get_side_data(frame, AV_FRAME_DATA_ICC_PROFILE);
    if (sd && sd->size) {
        const int nb_chunks = (sd->size + ICC_CHUNK_SIZE - 1) / ICC_CHUNK_SIZE;
        const uint8_t *data = sd->data;
        size_t remaining = sd->size;
        /* must already be checked by the packat allocation code */
        av_assert0(remaining <= ICC_MAX_CHUNKS * ICC_CHUNK_SIZE);
        flush_put_bits(p);
        for (int i = 0; i < nb_chunks; i++) {
            size = FFMIN(remaining, ICC_CHUNK_SIZE);
            av_assert1(size > 0);
            ptr = put_bits_ptr(p);
            ptr[0] = 0xff; /* chunk marker, not part of ICC_HDR_SIZE */
            ptr[1] = APP2;
            AV_WB16(ptr+2, size + ICC_HDR_SIZE);
            AV_WL32(ptr+4,  MKTAG('I','C','C','_'));
            AV_WL32(ptr+8,  MKTAG('P','R','O','F'));
            AV_WL32(ptr+12, MKTAG('I','L','E','\0'));
            ptr[16] = i+1;
            ptr[17] = nb_chunks;
            memcpy(&ptr[18], data, size);
            skip_put_bytes(p, size + ICC_HDR_SIZE + 2);
            remaining -= size;
            data += size;
        }
        av_assert1(!remaining);
    }

    /* comment */
    if (!(avctx->flags & AV_CODEC_FLAG_BITEXACT)) {
        put_marker(p, COM);
        flush_put_bits(p);
        ptr = put_bits_ptr(p);
        put_bits(p, 16, 0); /* patched later */
        ff_put_string(p, LIBAVCODEC_IDENT, 1);
        size = strlen(LIBAVCODEC_IDENT)+3;
        AV_WB16(ptr, size);
    }

    /* HDR Gain Map metadata */
    sd = av_frame_get_side_data(frame, AV_FRAME_DATA_HDR_GAINMAP);
    if (sd && sd->size >= sizeof(AVHDRGainMap)) {
        const AVHDRGainMap *gainmap = (const AVHDRGainMap *)sd->data;
        /* Default to XMP if no encoder context (e.g. lossless JPEG) */
        int gm_fmt = m ? m->gain_map_metadata : GAIN_MAP_METADATA_XMP;

        /* -- XMP / HDRGM APP1 ------------------------------------------- */
        if (gm_fmt == GAIN_MAP_METADATA_XMP) {
            static const char xmp_ns[] = "http://ns.adobe.com/xap/1.0/";
            char xmp_body[512];
            int xmp_body_len;
            const char *base_is_hdr = gainmap->base_rendition_is_hdr ? "True" : "False";

            xmp_body_len = snprintf(xmp_body, sizeof(xmp_body),
                "<?xpacket begin=\"\xef\xbb\xbf\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>"
                "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">"
                "<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">"
                "<rdf:Description rdf:about=\"\""
                " xmlns:hdrgm=\"http://ns.adobe.com/hdr-gain-map/1.0/\""
                " hdrgm:Version=\"1.0\""
                " hdrgm:GainMapMin=\"%.8g\""
                " hdrgm:GainMapMax=\"%.8g\""
                " hdrgm:Gamma=\"%.8g\""
                " hdrgm:OffsetSDR=\"%.8g\""
                " hdrgm:OffsetHDR=\"%.8g\""
                " hdrgm:HDRCapacityMin=\"%.8g\""
                " hdrgm:HDRCapacityMax=\"%.8g\""
                " hdrgm:BaseRenditionIsHDR=\"%s\"/>"
                "</rdf:RDF></x:xmpmeta>"
                "<?xpacket end=\"w\"?>",
                av_q2d(gainmap->gain_map_min[0]),
                av_q2d(gainmap->gain_map_max[0]),
                av_q2d(gainmap->gamma[0]),
                av_q2d(gainmap->base_offset[0]),
                av_q2d(gainmap->alternate_offset[0]),
                av_q2d(gainmap->base_hdr_headroom),
                av_q2d(gainmap->alternate_hdr_headroom),
                base_is_hdr);

            if (xmp_body_len > 0 && xmp_body_len < (int)sizeof(xmp_body)) {
                int app1_size = 2 /* marker */ + 2 /* length */ +
                                sizeof(xmp_ns) /* includes \0 */ +
                                xmp_body_len;
                flush_put_bits(p);
                ptr = put_bits_ptr(p);
                ptr[0] = 0xFF;
                ptr[1] = APP1;
                AV_WB16(ptr + 2, app1_size - 2);
                memcpy(ptr + 4, xmp_ns, sizeof(xmp_ns)); /* incl. null terminator */
                memcpy(ptr + 4 + sizeof(xmp_ns), xmp_body, xmp_body_len);
                skip_put_bytes(p, app1_size);
            }
        }

        /* -- ISO 21496-1 version-only APP2 (primary image marker) -------- *
         * Per ISO 21496-1 / Ultra HDR format: the primary JPEG carries a   *
         * version-only marker (4-byte payload: min_version + writer_version *
         * both zero).  The full metadata is in the secondary JPEG APP2.    */
        if (gm_fmt == GAIN_MAP_METADATA_ISO) {
            /* ISO namespace: "urn:iso:std:iso:ts:21496:-1\0" (28 bytes) */
            static const char iso_ns[] = "urn:iso:std:iso:ts:21496:-1";
            /* version-only payload: min_version(2) + writer_version(2) */
            static const uint8_t iso_ver[4] = { 0, 0, 0, 0 };
            int app2_size = 2 /* marker */ + 2 /* length */ +
                            sizeof(iso_ns) /* includes \0 */ + sizeof(iso_ver);
            flush_put_bits(p);
            ptr = put_bits_ptr(p);
            ptr[0] = 0xFF;
            ptr[1] = APP2;
            AV_WB16(ptr + 2, app2_size - 2);
            memcpy(ptr + 4, iso_ns, sizeof(iso_ns)); /* incl. null terminator */
            memcpy(ptr + 4 + sizeof(iso_ns), iso_ver, sizeof(iso_ver));
            skip_put_bytes(p, app2_size);
        }
    }

    if (((avctx->pix_fmt == AV_PIX_FMT_YUV420P ||
          avctx->pix_fmt == AV_PIX_FMT_YUV422P ||
          avctx->pix_fmt == AV_PIX_FMT_YUV444P) && avctx->color_range != AVCOL_RANGE_JPEG)
        || avctx->color_range == AVCOL_RANGE_MPEG) {
        put_marker(p, COM);
        flush_put_bits(p);
        ptr = put_bits_ptr(p);
        put_bits(p, 16, 0); /* patched later */
        ff_put_string(p, "CS=ITU601", 1);
        size = strlen("CS=ITU601")+3;
        AV_WB16(ptr, size);
    }
}

void ff_mjpeg_init_hvsample(const AVCodecContext *avctx, int hsample[4], int vsample[4])
{
    if (avctx->codec_id == AV_CODEC_ID_LJPEG &&
        (   avctx->pix_fmt == AV_PIX_FMT_BGR0
         || avctx->pix_fmt == AV_PIX_FMT_BGRA
         || avctx->pix_fmt == AV_PIX_FMT_BGR24)) {
        vsample[0] = hsample[0] =
        vsample[1] = hsample[1] =
        vsample[2] = hsample[2] =
        vsample[3] = hsample[3] = 1;
    } else if (avctx->pix_fmt == AV_PIX_FMT_YUV444P || avctx->pix_fmt == AV_PIX_FMT_YUVJ444P) {
        vsample[0] = vsample[1] = vsample[2] = 2;
        hsample[0] = hsample[1] = hsample[2] = 1;
    } else {
        int chroma_h_shift, chroma_v_shift;
        av_pix_fmt_get_chroma_sub_sample(avctx->pix_fmt, &chroma_h_shift,
                                         &chroma_v_shift);
        vsample[0] = 2;
        vsample[1] = 2 >> chroma_v_shift;
        vsample[2] = 2 >> chroma_v_shift;
        hsample[0] = 2;
        hsample[1] = 2 >> chroma_h_shift;
        hsample[2] = 2 >> chroma_h_shift;
    }
}

void ff_mjpeg_encode_picture_header(AVCodecContext *avctx, PutBitContext *pb,
                                    const AVFrame *frame, const struct MJpegContext *m,
                                    const uint8_t intra_matrix_permutation[64], int pred,
                                    const uint16_t luma_intra_matrix[64],
                                    const uint16_t chroma_intra_matrix[64],
                                    int use_slices)
{
    const int lossless = !m;
    int hsample[4], vsample[4];
    int components = 3 + (avctx->pix_fmt == AV_PIX_FMT_BGRA);
    int chroma_matrix;

    ff_mjpeg_init_hvsample(avctx, hsample, vsample);

    put_marker(pb, SOI);

    // hack for AMV mjpeg format
    if (avctx->codec_id == AV_CODEC_ID_AMV)
        return;

    jpeg_put_comments(avctx, pb, frame, m);

    chroma_matrix = !lossless && !!memcmp(luma_intra_matrix,
                                          chroma_intra_matrix,
                                          sizeof(luma_intra_matrix[0]) * 64);
    jpeg_table_header(avctx, pb, m, intra_matrix_permutation,
                      luma_intra_matrix, chroma_intra_matrix, hsample,
                      use_slices, chroma_matrix);

    switch (avctx->codec_id) {
    case AV_CODEC_ID_MJPEG:  put_marker(pb, SOF0 ); break;
    case AV_CODEC_ID_LJPEG:  put_marker(pb, SOF3 ); break;
    default: av_unreachable("ff_mjpeg_encode_picture_header only called by "
                            "AMV, LJPEG, MJPEG and the former has been ruled out");
    }

    put_bits(pb, 16, 8 + 3 * components);
    if (lossless && (  avctx->pix_fmt == AV_PIX_FMT_BGR0
                    || avctx->pix_fmt == AV_PIX_FMT_BGRA
                    || avctx->pix_fmt == AV_PIX_FMT_BGR24))
        put_bits(pb, 8, 9); /* 9 bits/component RCT */
    else
        put_bits(pb, 8, 8); /* 8 bits/component */
    put_bits(pb, 16, avctx->height);
    put_bits(pb, 16, avctx->width);
    put_bits(pb, 8, components); /* 3 or 4 components */

    /* Y component */
    put_bits(pb, 8, 1); /* component number */
    put_bits(pb, 4, hsample[0]); /* H factor */
    put_bits(pb, 4, vsample[0]); /* V factor */
    put_bits(pb, 8, 0); /* select matrix */

    /* Cb component */
    put_bits(pb, 8, 2); /* component number */
    put_bits(pb, 4, hsample[1]); /* H factor */
    put_bits(pb, 4, vsample[1]); /* V factor */
    put_bits(pb, 8, lossless ? 0 : chroma_matrix); /* select matrix */

    /* Cr component */
    put_bits(pb, 8, 3); /* component number */
    put_bits(pb, 4, hsample[2]); /* H factor */
    put_bits(pb, 4, vsample[2]); /* V factor */
    put_bits(pb, 8, lossless ? 0 : chroma_matrix); /* select matrix */

    if (components == 4) {
        put_bits(pb, 8, 4); /* component number */
        put_bits(pb, 4, hsample[3]); /* H factor */
        put_bits(pb, 4, vsample[3]); /* V factor */
        put_bits(pb, 8, 0); /* select matrix */
    }

    /* scan header */
    put_marker(pb, SOS);
    put_bits(pb, 16, 6 + 2*components); /* length */
    put_bits(pb, 8, components); /* 3 components */

    /* Y component */
    put_bits(pb, 8, 1); /* index */
    put_bits(pb, 4, 0); /* DC huffman table index */
    put_bits(pb, 4, 0); /* AC huffman table index */

    /* Cb component */
    put_bits(pb, 8, 2); /* index */
    put_bits(pb, 4, 1); /* DC huffman table index */
    put_bits(pb, 4, lossless ? 0 : 1); /* AC huffman table index */

    /* Cr component */
    put_bits(pb, 8, 3); /* index */
    put_bits(pb, 4, 1); /* DC huffman table index */
    put_bits(pb, 4, lossless ? 0 : 1); /* AC huffman table index */

    if (components == 4) {
        /* Alpha component */
        put_bits(pb, 8, 4); /* index */
        put_bits(pb, 4, 0); /* DC huffman table index */
        put_bits(pb, 4, 0); /* AC huffman table index */
    }

    put_bits(pb, 8, pred); /* Ss (not used); pred only nonzero for LJPEG */

    switch (avctx->codec_id) {
    case AV_CODEC_ID_MJPEG:  put_bits(pb, 8, 63); break; /* Se (not used) */
    case AV_CODEC_ID_LJPEG:  put_bits(pb, 8,  0); break; /* not used */
    default: av_unreachable("Only LJPEG, MJPEG possible here");
    }

    put_bits(pb, 8, 0); /* Ah/Al (not used) */
}

void ff_mjpeg_escape_FF(PutBitContext *pb, int start)
{
    int size;
    int i, ff_count;
    uint8_t *buf = pb->buf + start;
    int align= (-(size_t)(buf))&3;
    int pad = (-put_bits_count(pb))&7;

    if (pad)
        put_bits(pb, pad, (1<<pad)-1);

    flush_put_bits(pb);
    size = put_bytes_output(pb) - start;

    ff_count=0;
    for(i=0; i<size && i<align; i++){
        if(buf[i]==0xFF) ff_count++;
    }
    for(; i<size-15; i+=16){
        int acc, v;

        v= *(uint32_t*)(&buf[i]);
        acc= (((v & (v>>4))&0x0F0F0F0F)+0x01010101)&0x10101010;
        v= *(uint32_t*)(&buf[i+4]);
        acc+=(((v & (v>>4))&0x0F0F0F0F)+0x01010101)&0x10101010;
        v= *(uint32_t*)(&buf[i+8]);
        acc+=(((v & (v>>4))&0x0F0F0F0F)+0x01010101)&0x10101010;
        v= *(uint32_t*)(&buf[i+12]);
        acc+=(((v & (v>>4))&0x0F0F0F0F)+0x01010101)&0x10101010;

        acc>>=4;
        acc+= (acc>>16);
        acc+= (acc>>8);
        ff_count+= acc&0xFF;
    }
    for(; i<size; i++){
        if(buf[i]==0xFF) ff_count++;
    }

    if(ff_count==0) return;

    skip_put_bytes(pb, ff_count);

    for(i=size-1; ff_count; i--){
        int v= buf[i];

        if(v==0xFF){
            buf[i+ff_count]= 0;
            ff_count--;
        }

        buf[i+ff_count]= v;
    }
}

/* isn't this function nicer than the one in the libjpeg ? */
void ff_mjpeg_build_huffman_codes(uint8_t *huff_size, uint16_t *huff_code,
                                  const uint8_t *bits_table,
                                  const uint8_t *val_table)
{
    int k, code;

    k = 0;
    code = 0;
    for (int i = 1; i <= 16; i++) {
        int nb = bits_table[i];
        for (int j = 0; j < nb; j++) {
            int sym = val_table[k++];
            huff_size[sym] = i;
            huff_code[sym] = code;
            code++;
        }
        code <<= 1;
    }
}

void ff_mjpeg_encode_picture_trailer(PutBitContext *pb, int header_bits)
{
    av_assert1((header_bits & 7) == 0);

    put_marker(pb, EOI);
}

void ff_mjpeg_encode_dc(PutBitContext *pb, int val,
                        const uint8_t huff_size[], const uint16_t huff_code[])
{
    int mant, nbits;

    if (val == 0) {
        put_bits(pb, huff_size[0], huff_code[0]);
    } else {
        mant = val;
        if (val < 0) {
            val = -val;
            mant--;
        }

        nbits= av_log2_16bit(val) + 1;

        put_bits(pb, huff_size[nbits], huff_code[nbits]);

        put_sbits(pb, nbits, mant);
    }
}

int ff_mjpeg_encode_check_pix_fmt(AVCodecContext *avctx)
{
    if (avctx->strict_std_compliance > FF_COMPLIANCE_UNOFFICIAL &&
        avctx->color_range != AVCOL_RANGE_JPEG &&
        (avctx->pix_fmt == AV_PIX_FMT_YUV420P ||
         avctx->pix_fmt == AV_PIX_FMT_YUV422P ||
         avctx->pix_fmt == AV_PIX_FMT_YUV444P ||
         avctx->color_range == AVCOL_RANGE_MPEG)) {
        av_log(avctx, AV_LOG_ERROR,
               "Non full-range YUV is non-standard, set strict_std_compliance "
               "to at most unofficial to use it.\n");
        return AVERROR(EINVAL);
    }
    return 0;
}
