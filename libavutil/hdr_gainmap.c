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

#include "buffer.h"
#include "frame.h"
#include "hdr_gainmap.h"
#include "mem.h"

static void set_defaults(AVHDRGainMap *gainmap)
{
    for (int i = 0; i < 3; i++) {
        gainmap->gain_map_min[i]     = (AVRational){ -1, 1  };
        gainmap->gain_map_max[i]     = (AVRational){  1, 1  };
        gainmap->gamma[i]            = (AVRational){  1, 1  };
        gainmap->base_offset[i]      = (AVRational){  1, 64 };
        gainmap->alternate_offset[i] = (AVRational){  1, 64 };
    }
    gainmap->base_hdr_headroom      = (AVRational){ 0, 1 };
    gainmap->alternate_hdr_headroom = (AVRational){ 1, 1 };
    gainmap->base_rendition_is_hdr  = 0;
    gainmap->gain_map_frame         = NULL;
}

AVHDRGainMap *av_hdr_gainmap_alloc(size_t *size)
{
    AVHDRGainMap *gainmap = av_mallocz(sizeof(*gainmap));
    if (!gainmap)
        return NULL;

    set_defaults(gainmap);

    if (size)
        *size = sizeof(*gainmap);

    return gainmap;
}

void av_hdr_gainmap_free(AVHDRGainMap **gainmap)
{
    if (!gainmap || !*gainmap)
        return;
    av_frame_free(&(*gainmap)->gain_map_frame);
    av_freep(gainmap);
}

/**
 * AVBufferRef free callback: release gain_map_frame then free the struct.
 * This is called when the last reference to the side-data buffer is dropped.
 */
static void gainmap_buf_free(void *opaque, uint8_t *data)
{
    AVHDRGainMap *gainmap = (AVHDRGainMap *)data;
    av_frame_free(&gainmap->gain_map_frame);
    av_free(data);
}

AVHDRGainMap *av_hdr_gainmap_create_side_data(AVFrame *frame)
{
    AVHDRGainMap *gainmap;
    AVBufferRef *buf;
    AVFrameSideData *sd;

    gainmap = av_mallocz(sizeof(*gainmap));
    if (!gainmap)
        return NULL;

    set_defaults(gainmap);

    buf = av_buffer_create((uint8_t *)gainmap, sizeof(*gainmap),
                           gainmap_buf_free, NULL, 0);
    if (!buf) {
        av_free(gainmap);
        return NULL;
    }

    sd = av_frame_new_side_data_from_buf(frame, AV_FRAME_DATA_HDR_GAINMAP, buf);
    if (!sd) {
        av_buffer_unref(&buf); /* calls gainmap_buf_free */
        return NULL;
    }

    return (AVHDRGainMap *)sd->data;
}
