/*
 * H.264/HEVC/AV1 hardware encoding using nvidia nvenc
 * Copyright (c) 2025 Wang Bin <wbsecg1 at gmail.com>
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

// include a desired version of nvEncodeAPI.h first, so nvEncodeAPI.h included in nvenc.h will be ignored
#define FF_NVENC_DUP 1
#if __has_include(<nv-codec-headers-11.1/include/ffnvcodec/nvEncodeAPI.h>)
#include <nv-codec-headers-11.1/include/ffnvcodec/nvEncodeAPI.h>
#include "nvenc.c"
#endif