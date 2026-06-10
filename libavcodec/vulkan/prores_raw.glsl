/*
 * ProRes RAW Bayer helpers
 *
 * Copyright (c) 2026 WangBin <wbsecg1@gmail.com>
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

/* Logical component positions within a 2x2 Bayer cell: 0=R, 1/2=G, 3=B.
 * Indexed flat as [pattern*4 + component]. */
const u8vec2 bayer_comp_pos[16] = u8vec2[](
    u8vec2(0, 0), u8vec2(1, 0), u8vec2(0, 1), u8vec2(1, 1), /* 0 RGGB */
    u8vec2(1, 0), u8vec2(0, 0), u8vec2(1, 1), u8vec2(0, 1), /* 1 GRBG */
    u8vec2(1, 1), u8vec2(1, 0), u8vec2(0, 1), u8vec2(0, 0), /* 2 BGGR */
    u8vec2(0, 1), u8vec2(0, 0), u8vec2(1, 1), u8vec2(1, 0)  /* 3 GBRG */
);

ivec2 bayer_component_offs(uint pattern, uint comp)
{
    return ivec2(bayer_comp_pos[pattern*4u + comp]);
}
