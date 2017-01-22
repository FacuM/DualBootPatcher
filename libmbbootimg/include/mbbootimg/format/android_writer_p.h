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

#include <openssl/sha.h>

#include "mbbootimg/entry.h"
#include "mbbootimg/format/android_p.h"
#include "mbbootimg/header.h"
#include "mbbootimg/writer.h"

MB_BEGIN_C_DECLS

struct AndroidWriterCtx
{
    // Header values
    AndroidHeader hdr;

    // Header
    MbBiHeader *header;
    MbBiEntry *entry;

    // Position
    uint64_t pos;
    uint32_t entry_size;

    bool have_kernel_size;
    bool have_ramdisk_size;
    bool have_second_size;
    bool have_dt_size;

    AndroidState state;

    bool is_bump;

    SHA_CTX sha_ctx;
};

void android_writer_advance_state(struct AndroidWriterCtx *ctx);
void android_writer_update_size_if_unset(AndroidWriterCtx *ctx, uint32_t size);

int android_writer_get_header(MbBiWriter *biw, void *userdata,
                              MbBiHeader **header);
int android_writer_write_header(MbBiWriter *biw, void *userdata,
                                MbBiHeader *header);
int android_writer_get_entry(MbBiWriter *biw, void *userdata,
                             MbBiEntry **entry);
int android_writer_write_entry(MbBiWriter *biw, void *userdata,
                               MbBiEntry *entry);
int android_writer_write_data(MbBiWriter *biw, void *userdata,
                              const void *buf, size_t buf_size,
                              size_t *bytes_written);
int android_writer_close(MbBiWriter *biw, void *userdata);
int android_writer_free(MbBiWriter *bir, void *userdata);

MB_END_C_DECLS
