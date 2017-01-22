/*
 * Copyright (C) 2017  Andrew Gunnerson <andrewgunnerson@gmail.com>
 *
 * This file is part of MultiBootPatcher
 *
 * MultiBootPatcher is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * MultiBootPatcher is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with MultiBootPatcher.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "mbbootimg/guard_p.h"

#ifdef __cplusplus
#  include <cstdint>
#else
#  include <stdint.h>
#endif

#include "mbcommon/common.h"
#include "mbcommon/endian.h"

#define LOKI_MAGIC              "LOKI"
#define LOKI_MAGIC_SIZE         4
#define LOKI_MAGIC_OFFSET       0x400

#define LOKI_SHELLCODE          \
        "\xfe\xb5"              \
        "\x0d\x4d"              \
        "\xd5\xf8"              \
        "\x88\x04"              \
        "\xab\x68"              \
        "\x98\x42"              \
        "\x12\xd0"              \
        "\xd5\xf8"              \
        "\x90\x64"              \
        "\x0a\x4c"              \
        "\xd5\xf8"              \
        "\x8c\x74"              \
        "\x07\xf5\x80\x57"      \
        "\x0f\xce"              \
        "\x0f\xc4"              \
        "\x10\x3f"              \
        "\xfb\xdc"              \
        "\xd5\xf8"              \
        "\x88\x04"              \
        "\x04\x49"              \
        "\xd5\xf8"              \
        "\x8c\x24"              \
        "\xa8\x60"              \
        "\x69\x61"              \
        "\x2a\x61"              \
        "\x00\x20"              \
        "\xfe\xbd"              \
        "\xff\xff\xff\xff"      \
        "\xee\xee\xee\xee"

#define LOKI_SHELLCODE_SIZE     65 // sizeof(LOKI_SHELLCODE)


struct LokiHeader
{
    unsigned char magic[4]; /* 0x494b4f4c */
    uint32_t recovery;      /* 0 = boot.img, 1 = recovery.img */
    char build[128];        /* Build number */

    uint32_t orig_kernel_size;
    uint32_t orig_ramdisk_size;
    uint32_t ramdisk_addr;
};

MB_BEGIN_C_DECLS

static inline void loki_fix_header_byte_order(LokiHeader *header)
{
    header->recovery = mb_le32toh(header->recovery);
    header->orig_kernel_size = mb_le32toh(header->orig_kernel_size);
    header->orig_ramdisk_size = mb_le32toh(header->orig_ramdisk_size);
    header->ramdisk_addr = mb_le32toh(header->ramdisk_addr);
}

MB_END_C_DECLS
