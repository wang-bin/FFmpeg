/*
 * HDR Gain Map application filter
 * Copyright (c) 2024 FFmpeg contributors
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

/**
 * @file
 * HDR gain map application filter (applygainmap).
 *
 * Reads an AV_FRAME_DATA_HDR_GAINMAP side data entry from the input frame,
 * applies the gain map formula (ISO 21496-1 / Ultra HDR) and outputs a
 * linear-light HDR image in AV_PIX_FMT_GBRPF32.
 *
 * The application formula per channel c is:
 *   W     = clamp((target_headroom - base_hdr_headroom) /
 *                 (alternate_hdr_headroom - base_hdr_headroom), 0, 1)
 *   gain  = gainmap^(1/gamma[c]) * (gain_max[c] - gain_min[c]) + gain_min[c]
 *   HDR   = (SDR_linear + base_offset[c]) * 2^(gain * W) - alternate_offset[c]
 */

#include <math.h>

#include "libavutil/hdr_gainmap.h"
#include "libavutil/imgutils.h"
#include "libavutil/opt.h"
#include "libavutil/pixdesc.h"

#include "avfilter.h"
#include "filters.h"
#include "formats.h"
#include "video.h"

/** Minimum meaningful denominator / gamma value before treating as 0. */
#define GAINMAP_EPSILON 1e-6

typedef struct ApplyGainMapContext {
    const AVClass *class;

    /**
     * Target display HDR headroom (log2 stops).  The output is adapted to
     * this headroom.  Default 1.0 (= 2× SDR, equivalent to full gain map).
     */
    double target_headroom;
} ApplyGainMapContext;

#define OFFSET(x) offsetof(ApplyGainMapContext, x)
#define FLAGS (AV_OPT_FLAG_VIDEO_PARAM | AV_OPT_FLAG_FILTERING_PARAM)

static const AVOption applygainmap_options[] = {
    { "headroom", "target HDR headroom in log2 stops",
      OFFSET(target_headroom), AV_OPT_TYPE_DOUBLE,
      { .dbl = 1.0 }, 0.0, 16.0, FLAGS },
    { NULL }
};

AVFILTER_DEFINE_CLASS(applygainmap);

/* --------------------------------------------------------------------------
 * Colour-space helpers
 * -------------------------------------------------------------------------- */

/** Convert a normalised sRGB value [0, 1] to linear light. */
static inline float srgb_to_linear(float v)
{
    if (v <= 0.04045f)
        return v / 12.92f;
    return powf((v + 0.055f) / 1.055f, 2.4f);
}

/* --------------------------------------------------------------------------
 * Format negotiation
 * -------------------------------------------------------------------------- */

static const enum AVPixelFormat input_pix_fmts[] = {
    AV_PIX_FMT_YUVJ420P,
    AV_PIX_FMT_YUVJ422P,
    AV_PIX_FMT_YUVJ444P,
    AV_PIX_FMT_YUV420P,
    AV_PIX_FMT_YUV422P,
    AV_PIX_FMT_YUV444P,
    AV_PIX_FMT_RGB24,
    AV_PIX_FMT_GBRPF32,  /* pass-through if already linear */
    AV_PIX_FMT_NONE
};

static int query_formats(const AVFilterContext *ctx,
                         AVFilterFormatsConfig **cfg_in,
                         AVFilterFormatsConfig **cfg_out)
{
    AVFilterFormats *in_formats  = ff_make_pixel_format_list(input_pix_fmts);
    AVFilterFormats *out_formats = NULL;
    int ret;

    if (!in_formats)
        return AVERROR(ENOMEM);

    ret = ff_add_format(&out_formats, AV_PIX_FMT_GBRPF32);
    if (ret < 0) {
        ff_formats_unref(&in_formats);
        return ret;
    }

    ret = ff_formats_ref(in_formats, &cfg_in[0]->formats);
    if (ret < 0) {
        ff_formats_unref(&out_formats);
        return ret;
    }

    return ff_formats_ref(out_formats, &cfg_out[0]->formats);
}

/* --------------------------------------------------------------------------
 * Gain-map pixel sampling (nearest-neighbour)
 * -------------------------------------------------------------------------- */

/**
 * Sample the gain map at position (@p sx, @p sy) and return a value in
 * [0.0, 1.0].  Uses the first (luma/green) plane.
 */
static float gainmap_sample(const AVFrame *gm, int sx, int sy)
{
    const AVPixFmtDescriptor *desc = av_pix_fmt_desc_get(gm->format);

    if (!desc || !gm->data[0])
        return 0.5f;

    if (desc->comp[0].depth <= 8) {
        return gm->data[0][sy * gm->linesize[0] + sx] / 255.0f;
    } else {
        /* 16-bit big-endian (AV_PIX_FMT_GRAY16BE) */
        const uint8_t *p = gm->data[0] + sy * gm->linesize[0] + sx * 2;
        return (uint16_t)((p[0] << 8) | p[1]) / 65535.0f;
    }
}

/* --------------------------------------------------------------------------
 * filter_frame
 * -------------------------------------------------------------------------- */

static int filter_frame(AVFilterLink *inlink, AVFrame *in)
{
    AVFilterContext     *ctx     = inlink->dst;
    ApplyGainMapContext *s       = ctx->priv;
    AVFilterLink        *outlink = ctx->outputs[0];
    const AVFrameSideData *sd;
    const AVHDRGainMap  *gainmap;
    const AVFrame       *gm;
    AVFrame             *out;
    float                W;
    int                  ret;

    /* Require a gain map side data entry */
    sd = av_frame_get_side_data(in, AV_FRAME_DATA_HDR_GAINMAP);
    if (!sd || sd->size < sizeof(AVHDRGainMap)) {
        av_log(ctx, AV_LOG_WARNING,
               "applygainmap: no HDR gain map found on input frame; "
               "passing frame through unchanged\n");
        return ff_filter_frame(outlink, in);
    }

    gainmap = (const AVHDRGainMap *)sd->data;
    gm      = gainmap->gain_map_frame;

    if (!gm || gm->width <= 0 || gm->height <= 0) {
        av_log(ctx, AV_LOG_WARNING,
               "applygainmap: gain map frame is missing or empty; "
               "passing frame through unchanged\n");
        return ff_filter_frame(outlink, in);
    }

    /* Allocate output GBRPF32 frame */
    out = ff_get_video_buffer(outlink, in->width, in->height);
    if (!out) {
        av_frame_free(&in);
        return AVERROR(ENOMEM);
    }
    ret = av_frame_copy_props(out, in);
    if (ret < 0) {
        av_frame_free(&out);
        av_frame_free(&in);
        return ret;
    }

    /* Set output colorspace metadata */
    out->color_primaries = AVCOL_PRI_BT2020;
    out->color_trc       = AVCOL_TRC_LINEAR;
    out->colorspace      = AVCOL_SPC_BT2020_NCL;
    out->color_range     = AVCOL_RANGE_JPEG;

    /* Remove the gain map side data from the output (it has been applied) */
    av_frame_remove_side_data(out, AV_FRAME_DATA_HDR_GAINMAP);

    /* Pre-compute blending weight W */
    {
        double base_hr = av_q2d(gainmap->base_hdr_headroom);
        double alt_hr  = av_q2d(gainmap->alternate_hdr_headroom);
        double denom   = alt_hr - base_hr;
        W = (denom < GAINMAP_EPSILON) ? 1.0f
                           : (float)((s->target_headroom - base_hr) / denom);
        W = av_clipf(W, 0.0f, 1.0f);
    }

    /* Pre-compute per-channel parameters */
    float gmin[3], gmax[3], ginv[3], boff[3], aoff[3];
    for (int c = 0; c < 3; c++) {
        gmin[c] = (float)av_q2d(gainmap->gain_map_min[c]);
        gmax[c] = (float)av_q2d(gainmap->gain_map_max[c]);
        float g = (float)av_q2d(gainmap->gamma[c]);
        ginv[c] = (g > (float)GAINMAP_EPSILON) ? 1.0f / g : 1.0f;
        boff[c] = (float)av_q2d(gainmap->base_offset[c]);
        aoff[c] = (float)av_q2d(gainmap->alternate_offset[c]);
    }

    int w    = in->width;
    int h    = in->height;
    int gm_w = gm->width;
    int gm_h = gm->height;
    enum AVPixelFormat in_fmt = in->format;
    int chroma_shift_h = 0, chroma_shift_v = 0;

    if (!(av_pix_fmt_desc_get(in_fmt)->flags & AV_PIX_FMT_FLAG_RGB))
        av_pix_fmt_get_chroma_sub_sample(in_fmt, &chroma_shift_h, &chroma_shift_v);

    for (int y = 0; y < h; y++) {
        /* Nearest-neighbour gain map row mapping */
        int gy = av_clip((int)((y + 0.5f) * gm_h / h), 0, gm_h - 1);

        /* GBRPF32 output plane pointers: plane 0=G, 1=B, 2=R */
        float *out_g = (float *)(out->data[0] + y * out->linesize[0]);
        float *out_b = (float *)(out->data[1] + y * out->linesize[1]);
        float *out_r = (float *)(out->data[2] + y * out->linesize[2]);

        for (int x = 0; x < w; x++) {
            int gx = av_clip((int)((x + 0.5f) * gm_w / w), 0, gm_w - 1);
            float gmap_val = gainmap_sample(gm, gx, gy);

            float sdr[3]; /* linear-light R, G, B */

            if (in_fmt == AV_PIX_FMT_GBRPF32) {
                /* Already linear – just read the planes */
                sdr[0] = ((const float *)(in->data[2] + y * in->linesize[2]))[x]; /* R */
                sdr[1] = ((const float *)(in->data[0] + y * in->linesize[0]))[x]; /* G */
                sdr[2] = ((const float *)(in->data[1] + y * in->linesize[1]))[x]; /* B */
            } else if (av_pix_fmt_desc_get(in_fmt)->flags & AV_PIX_FMT_FLAG_RGB) {
                /* Packed RGB24 – 8-bit sRGB */
                const uint8_t *px = in->data[0] + y * in->linesize[0] + x * 3;
                sdr[0] = srgb_to_linear(px[0] / 255.0f);
                sdr[1] = srgb_to_linear(px[1] / 255.0f);
                sdr[2] = srgb_to_linear(px[2] / 255.0f);
            } else {
                /* Planar YUV – BT.601 full-range → linear RGB */
                int uv_y = y >> chroma_shift_v;
                int uv_x = x >> chroma_shift_h;
                float Y  = in->data[0][y    * in->linesize[0] + x   ] / 255.0f;
                float Cb = in->data[1][uv_y * in->linesize[1] + uv_x] / 255.0f - 0.5f;
                float Cr = in->data[2][uv_y * in->linesize[2] + uv_x] / 255.0f - 0.5f;
                float R  = av_clipf(Y +  1.402f   * Cr,              0.0f, 1.0f);
                float G  = av_clipf(Y - 0.34414f  * Cb - 0.71414f * Cr, 0.0f, 1.0f);
                float B  = av_clipf(Y +  1.772f   * Cb,              0.0f, 1.0f);
                sdr[0] = srgb_to_linear(R);
                sdr[1] = srgb_to_linear(G);
                sdr[2] = srgb_to_linear(B);
            }

            /* Apply gain map formula per channel */
            for (int c = 0; c < 3; c++) {
                float g    = powf(gmap_val, ginv[c]);
                float gain = g * (gmax[c] - gmin[c]) + gmin[c];
                sdr[c] = (sdr[c] + boff[c]) * exp2f(gain * W) - aoff[c];
            }

            /* Store in GBRPF32 (plane order G=0, B=1, R=2) */
            out_g[x] = sdr[1];
            out_b[x] = sdr[2];
            out_r[x] = sdr[0];
        }
    }

    av_frame_free(&in);
    return ff_filter_frame(outlink, out);
}

static int config_output(AVFilterLink *outlink)
{
    AVFilterLink *inlink = outlink->src->inputs[0];

    outlink->w                   = inlink->w;
    outlink->h                   = inlink->h;
    outlink->time_base           = inlink->time_base;
    outlink->sample_aspect_ratio = inlink->sample_aspect_ratio;

    return 0;
}

static const AVFilterPad applygainmap_inputs[] = {
    {
        .name         = "default",
        .type         = AVMEDIA_TYPE_VIDEO,
        .filter_frame = filter_frame,
    },
};

static const AVFilterPad applygainmap_outputs[] = {
    {
        .name         = "default",
        .type         = AVMEDIA_TYPE_VIDEO,
        .config_props = config_output,
    },
};

const FFFilter ff_vf_applygainmap = {
    .p.name        = "applygainmap",
    .p.description = NULL_IF_CONFIG_SMALL(
        "Apply HDR gain map to reconstruct a high dynamic range image."),
    .p.priv_class  = &applygainmap_class,
    .priv_size     = sizeof(ApplyGainMapContext),
    FILTER_QUERY_FUNC2(query_formats),
    FILTER_INPUTS(applygainmap_inputs),
    FILTER_OUTPUTS(applygainmap_outputs),
};
