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
#  include <type_traits>
#endif

#ifdef __cplusplus
#  include <cstdint>
#else
#  include <stdint.h>
#endif

#include "mbcommon/common.h"
#include "mbcommon/endian.h"

#define BOOT_MAGIC                      "ANDROID!"
#define BOOT_MAGIC_SIZE                 8
#define BOOT_NAME_SIZE                  16
#define BOOT_ARGS_SIZE                  512

#define ANDROID_MAX_HEADER_OFFSET       512

#define SAMSUNG_SEANDROID_MAGIC         "SEANDROIDENFORCE"
#define SAMSUNG_SEANDROID_MAGIC_SIZE    16

#define ANDROID_SUPPORTED_FIELDS \
        (MB_BI_HEADER_FIELD_KERNEL_SIZE \
        | MB_BI_HEADER_FIELD_KERNEL_ADDRESS \
        | MB_BI_HEADER_FIELD_RAMDISK_SIZE \
        | MB_BI_HEADER_FIELD_RAMDISK_ADDRESS \
        | MB_BI_HEADER_FIELD_SECONDBOOT_SIZE \
        | MB_BI_HEADER_FIELD_SECONDBOOT_ADDRESS \
        | MB_BI_HEADER_FIELD_KERNEL_TAGS_ADDRESS \
        | MB_BI_HEADER_FIELD_PAGE_SIZE \
        | MB_BI_HEADER_FIELD_DEVICE_TREE_SIZE \
        | MB_BI_HEADER_FIELD_UNUSED \
        | MB_BI_HEADER_FIELD_BOARD_NAME \
        | MB_BI_HEADER_FIELD_KERNEL_CMDLINE \
        | MB_BI_HEADER_FIELD_ID)

struct AndroidHeader
{
    unsigned char magic[BOOT_MAGIC_SIZE];

    uint32_t kernel_size;   /* size in bytes */
    uint32_t kernel_addr;   /* physical load addr */

    uint32_t ramdisk_size;  /* size in bytes */
    uint32_t ramdisk_addr;  /* physical load addr */

    uint32_t second_size;   /* size in bytes */
    uint32_t second_addr;   /* physical load addr */

    uint32_t tags_addr;     /* physical addr for kernel tags */
    uint32_t page_size;     /* flash page size we assume */
    uint32_t dt_size;       /* device tree in bytes */
    uint32_t unused;        /* future expansion: should be 0 */
    unsigned char name[BOOT_NAME_SIZE]; /* asciiz product name */

    unsigned char cmdline[BOOT_ARGS_SIZE];

    uint32_t id[8]; /* timestamp / checksum / sha1 / etc */
};

enum class AndroidState
{
    START,
    KERNEL,
    RAMDISK,
    SECONDBOOT,
    DT,
    END,
};

#ifdef __cplusplus
template<typename T>
static inline T align_page_size(const T item_size, const T page_size)
{
    static_assert(!std::is_signed<T>::value, "Type is not unsigned");

    T mask = page_size - 1;

    if (!(item_size & mask)) {
        return 0;
    }

    return page_size - (item_size & mask);
}
#endif

MB_BEGIN_C_DECLS

static inline void android_fix_header_byte_order(AndroidHeader *header)
{
    header->kernel_size = mb_le32toh(header->kernel_size);
    header->kernel_addr = mb_le32toh(header->kernel_addr);
    header->ramdisk_size = mb_le32toh(header->ramdisk_size);
    header->ramdisk_addr = mb_le32toh(header->ramdisk_addr);
    header->second_size = mb_le32toh(header->second_size);
    header->second_addr = mb_le32toh(header->second_addr);
    header->tags_addr = mb_le32toh(header->tags_addr);
    header->page_size = mb_le32toh(header->page_size);
    header->dt_size = mb_le32toh(header->dt_size);
    header->unused = mb_le32toh(header->unused);

    // We read the ID directly, not as integers, so don't change the byte order
    //for (size_t i = 0; i < sizeof(header->id) / sizeof(header->id[0]); ++i) {
    //    header->id[i] = mb_le32toh(header->id[i]);
    //}
}

MB_END_C_DECLS
