/*
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

#ifndef AVUTIL_HDR_GAINMAP_H
#define AVUTIL_HDR_GAINMAP_H

#include <stddef.h>

#include "frame.h"
#include "rational.h"

/**
 * HDR Gain Map metadata, as defined by ISO 21496-1 / Ultra HDR.
 *
 * A gain map is a secondary image that, combined with a base (SDR) image,
 * allows reconstruction of an HDR image at an arbitrary display headroom.
 *
 * The application formula (per channel, in linear light) is:
 * @code
 *   W     = clamp((target_headroom - base_hdr_headroom) /
 *                 (alternate_hdr_headroom - base_hdr_headroom), 0, 1)
 *   gain  = gainmap_pixel^(1/gamma) * (gain_map_max - gain_map_min) + gain_map_min
 *   HDR   = (SDR + base_offset) * 2^(gain * W) - alternate_offset
 * @endcode
 *
 * All vector parameters have one entry per colour channel in R, G, B order.
 * When a single value applies to all channels it is stored in index 0;
 * indices 1 and 2 are identical in that case.
 *
 * @note sizeof(AVHDRGainMap) is not part of the public ABI.  Always allocate
 *       instances with av_hdr_gainmap_alloc().
 */
typedef struct AVHDRGainMap {
    /**
     * Minimum log2 gain map value, per channel.
     * Default: { -1/1, -1/1, -1/1 }.
     */
    AVRational gain_map_min[3];

    /**
     * Maximum log2 gain map value, per channel.
     * Default: { 1/1, 1/1, 1/1 }.
     */
    AVRational gain_map_max[3];

    /**
     * Gamma applied to the gain map image values before use, per channel.
     * Default: { 1/1, 1/1, 1/1 }.
     */
    AVRational gamma[3];

    /**
     * Offset added to base (SDR) pixel values before computing the gain
     * ratio, per channel.  Default: { 1/64, 1/64, 1/64 } (= 0.015625).
     */
    AVRational base_offset[3];

    /**
     * Offset subtracted from the reconstructed HDR pixel values, per channel.
     * Default: { 1/64, 1/64, 1/64 } (= 0.015625).
     */
    AVRational alternate_offset[3];

    /**
     * log2 of the HDR capacity of the base (SDR) rendition.
     * Typically 0.  Default: { 0, 1 }.
     */
    AVRational base_hdr_headroom;

    /**
     * log2 of the HDR capacity of the alternate (HDR) rendition.
     * Represents the maximum HDR boost that the gain map can apply.
     * Default: { 1, 1 }.
     */
    AVRational alternate_hdr_headroom;

    /**
     * Whether the base rendition is HDR (1) or SDR (0).  Default: 0.
     */
    int base_rendition_is_hdr;

    /**
     * The decoded gain map image.  Typically AV_PIX_FMT_GRAY8,
     * AV_PIX_FMT_GRAY16BE, or AV_PIX_FMT_YUVJ420P (luma used as gain map).
     * NULL when only the metadata fields are available.
     *
     * This frame is owned by the AVHDRGainMap structure and is freed together
     * with it (see av_hdr_gainmap_free()).
     */
    AVFrame *gain_map_frame;
} AVHDRGainMap;

/**
 * Allocate an AVHDRGainMap structure and initialise all fields to their
 * default values.
 *
 * @param size  if non-NULL, set to sizeof(AVHDRGainMap) on success
 * @return      the newly allocated structure, or NULL on allocation failure
 */
AVHDRGainMap *av_hdr_gainmap_alloc(size_t *size);

/**
 * Free an AVHDRGainMap and all resources it owns (including gain_map_frame).
 * Sets *gainmap to NULL.
 */
void av_hdr_gainmap_free(AVHDRGainMap **gainmap);

/**
 * Allocate an AVHDRGainMap and add it as side data to an existing AVFrame.
 *
 * The returned pointer remains valid until the side data entry is removed
 * from the frame or the frame is unreffed.
 *
 * @return the newly allocated structure, or NULL on failure
 */
AVHDRGainMap *av_hdr_gainmap_create_side_data(AVFrame *frame);

#endif /* AVUTIL_HDR_GAINMAP_H */
