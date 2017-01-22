/*
 * Copyright (C) 2015-2017  Andrew Gunnerson <andrewgunnerson@gmail.com>
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

#include "mbbootimg/format/loki_reader_p.h"

// #include <algorithm>
// #include <type_traits>
//
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstring>

#include "mbcommon/endian.h"
#include "mbcommon/file.h"
#include "mbcommon/string.h"

#include "mbbootimg/entry.h"
#include "mbbootimg/file_p.h"
#include "mbbootimg/header.h"
#include "mbbootimg/reader.h"
#include "mbbootimg/reader_p.h"

// TODO TODO TODO
#define LOKI_MAX_HEADER_OFFSET      32
// TODO TODO TODO

MB_BEGIN_C_DECLS

void loki_reader_advance_state(LokiReaderCtx *const ctx)
{
    switch (ctx->state) {
    case LokiState::START:
        ctx->state = LokiState::KERNEL;
        break;
    case LokiState::KERNEL:
        ctx->state = LokiState::RAMDISK;
        break;
    case LokiState::RAMDISK:
        if (ctx->hdr.second_size > 0) {
            ctx->state = LokiState::SECONDBOOT;
        } else if (ctx->hdr.dt_size > 0) {
            ctx->state = LokiState::DT;
        } else {
            ctx->state = LokiState::END;
        }
        break;
    case LokiState::SECONDBOOT:
        if (ctx->hdr.dt_size > 0) {
            ctx->state = LokiState::DT;
        } else {
            ctx->state = LokiState::END;
        }
        break;
    case LokiState::DT:
        ctx->state = LokiState::END;
        break;
    case LokiState::END:
        break;
    }
}

/*!
 * \brief Find and read Android boot image header
 *
 * \note The integral fields in the header will be converted to the host's byte
 *       order.
 *
 * \post The file pointer position is undefined after this function returns.
 *       Use mb_file_seek() to return to a known position.
 *
 * \param[in] bir MbBiReader
 * \param[out] header_out Pointer to store header
 * \param[out] offset_out Pointer to store header offset
 *
 * \return
 *   * MB_BI_OK if the header was found
 *   * MB_BI_WARN if the header was not found
 *   * MB_BI_FAILED if any file operations fail non-fatally
 *   * MB_BI_FATAL if any file operations fail fatally
 */
static int find_header(MbBiReader *bir, AndroidHeader *header_out,
                       uint64_t *offset_out)
{
    unsigned char buf[LOKI_MAX_HEADER_OFFSET + sizeof(AndroidHeader)];
    size_t buf_size;
    int ret;
    void *ptr;
    size_t offset;

    ret = mb_file_seek(bir->file, 0, SEEK_SET, nullptr);
    if (ret < 0) {
        mb_bi_reader_set_error(bir, mb_file_error(bir->file),
                               "Failed to seek to beginning of file: %s",
                               mb_file_error_string(bir->file));
        return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
    }

    ret = _mb_bi_read_fully(bir->file, buf, sizeof(buf), &buf_size);
    if (ret < 0) {
        mb_bi_reader_set_error(bir, mb_file_error(bir->file),
                               "Failed to read header: %s",
                               mb_file_error_string(bir->file));
        return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
    }

    ptr = mb_memmem(buf, buf_size, BOOT_MAGIC, BOOT_MAGIC_SIZE);
    if (!ptr) {
        mb_bi_reader_set_error(bir, MB_BI_ERROR_FILE_FORMAT,
                               "Boot magic not found in first %d bytes",
                               LOKI_MAX_HEADER_OFFSET);
        return MB_BI_WARN;
    }

    offset = static_cast<unsigned char *>(ptr) - buf;

    if (buf_size - offset < sizeof(AndroidHeader)) {
        mb_bi_reader_set_error(bir, MB_BI_ERROR_FILE_FORMAT,
                               "Boot magic found at %" PRIu64
                               ", but header exceeds file size",
                               offset);
        return MB_BI_WARN;
    }

    // Copy header
    memcpy(header_out, ptr, sizeof(AndroidHeader));
    android_fix_header_byte_order(header_out);
    *offset_out = offset;

    return MB_BI_OK;
}

/*!
 * \brief Find and read Loki boot image header
 *
 * \note The integral fields in the header will be converted to the host's byte
 *       order.
 *
 * \post The file pointer position is undefined after this function returns.
 *       Use mb_file_seek() to return to a known position.
 *
 * \param[in] bir MbBiReader
 * \param[out] header_out Pointer to store header
 * \param[out] offset_out Pointer to store header offset
 *
 * \return
 *   * MB_BI_OK if the header was found
 *   * MB_BI_WARN if the header was not found
 *   * MB_BI_FAILED if any file operations fail non-fatally
 *   * MB_BI_FATAL if any file operations fail fatally
 */
static int find_loki_header(MbBiReader *bir, LokiHeader *header_out,
                            uint64_t *offset_out)
{
    LokiHeader header;
    size_t n;
    int ret;

    ret = mb_file_seek(bir->file, LOKI_MAGIC_OFFSET, SEEK_SET, nullptr);
    if (ret < 0) {
        mb_bi_reader_set_error(bir, mb_file_error(bir->file),
                               "Failed to seek to Loki header: %s",
                               mb_file_error_string(bir->file));
        return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
    }

    ret = _mb_bi_read_fully(bir->file, &header, sizeof(header), &n);
    if (ret < 0) {
        mb_bi_reader_set_error(bir, mb_file_error(bir->file),
                               "Failed to read header: %s",
                               mb_file_error_string(bir->file));
        return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
    } else if (n != sizeof(header)) {
        mb_bi_reader_set_error(bir, MB_BI_ERROR_FILE_FORMAT,
                               "Too small to be Loki image");
        return MB_BI_WARN;
    }

    if (memcmp(header.magic, LOKI_MAGIC, LOKI_MAGIC_SIZE) != 0) {
        mb_bi_reader_set_error(bir, MB_BI_ERROR_FILE_FORMAT,
                               "Loki magic not found");
        return MB_BI_WARN;
    }

    loki_fix_header_byte_order(&header);
    *header_out = header;
    *offset_out = LOKI_MAGIC_OFFSET;

    return MB_BI_OK;
}

static uint32_t loki_find_ramdisk_address(MbBiReader *bir,
                                          const void *data, std::size_t size,
                                          const AndroidHeader *hdr,
                                          const LokiHeader *loki_hdr)
{
    // If the boot image was patched with a newer version of loki, find the
    // ramdisk offset in the shell code
    uint32_t ramdisk_addr = 0;

    if (loki_hdr->ramdisk_addr != 0) {
        for (uint32_t i = 0; i < size - (LOKI_SHELLCODE_SIZE - 9); ++i) {
            if (std::memcmp(&data[i], LOKI_SHELLCODE, LOKI_SHELLCODE_SIZE - 9) == 0) {
                ramdiskAddr = *(reinterpret_cast<const uint32_t *>(
                        &data[i] + LOKI_SHELLCODE_SIZE - 5));
                break;
            }
        }

        if (ramdiskAddr == 0) {
            LOGW("Couldn't determine ramdisk offset");
            return 0;
        }

        LOGD("Original ramdisk address: 0x%08x", ramdiskAddr);
    } else {
        // Otherwise, use the default for jflte (- 0x00008000 + 0x02000000)

        if (hdr->kernel_addr > UINT32_MAX - 0x01ff8000) {
            mb_bi_reader_set_error(bir, MB_BI_ERROR_FILE_FORMAT,
                                   "Invalid kernel address: %" PRIu32,
                                   hdr->kernel_addr);
            return 0;
        }

        ramdisk_addr = hdr->kernel_addr + 0x01ff8000;
    }

    return ramdisk_addr;
}

static int loki_read_old_header(MbBiReader *bir, LokiReaderCtx *ctx,
                                MbBiHeader *header)
{
    // TODO
}

static int loki_read_new_header(MbBiReader *bir, LokiReaderCtx *ctx,
                                MbBiHeader *header)
{
    uint32_t page_mask;
    uint32_t fake_size;

    if (ctx->hdr.page_size == 0) {
        mb_bi_reader_set_error(bir, MB_BI_ERROR_FILE_FORMAT,
                               "Page size cannot be 0");
        return MB_BI_FAILED;
    }

    page_mask = ctx->hdr.page_size - 1;

    // From loki_unlok.c
    if (ctx->hdr.ramdisk_addr > 0x88f00000
            || ctx->hdr.ramdisk_addr < 0xfa00000) {
        fake_size = ctx->hdr.page_size;
    } else {
        fake_size = 0x200;
    }

    // Find original ramdisk address
    uint32_t ramdiskAddr = lokiFindRamdiskAddress(data, size, loki);
    if (ramdiskAddr == 0) {
        LOGE("Could not find ramdisk address in new loki boot image");
        return false;
    }
}

/*!
 * \brief Perform a bid
 *
 * \return
 *   * If \>= 0, the number of bits that conform to the Loki format
 *   * MB_BI_WARN if this is a bid that can't be won
 *   * MB_BI_FAILED if any file operations fail non-fatally
 *   * MB_BI_FATAL if any file operations fail fatally
 */
int loki_reader_bid(MbBiReader *bir, void *userdata, int best_bid)
{
    LokiReaderCtx *const ctx = static_cast<LokiReaderCtx *>(userdata);
    int bid = 0;
    int ret;

    if (best_bid >= (BOOT_MAGIC_SIZE + LOKI_MAGIC_SIZE) * 8) {
        // This is a bid we can't win, so bail out
        return MB_BI_WARN;
    }

    // Find the Loki header
    ret = find_loki_header(bir, &ctx->loki_hdr, &ctx->loki_offset);
    if (ret == MB_BI_OK) {
        // Update bid to account for matched bits
        ctx->have_loki_offset = true;
        bid += LOKI_MAGIC_SIZE * 8;
    } else if (ret == MB_BI_WARN) {
        // Header not found. This can't be a Loki boot image.
        return 0;
    } else {
        return ret;
    }

    // Find the Android header
    ret = find_header(bir, &ctx->hdr, &ctx->header_offset);
    if (ret == MB_BI_OK) {
        // Update bid to account for matched bits
        ctx->have_header_offset = true;
        bid += BOOT_MAGIC_SIZE * 8;
    } else if (ret == MB_BI_WARN) {
        // Header not found. This can't be an Android boot image.
        return 0;
    } else {
        return ret;
    }

    return bid;
}

int loki_reader_read_header(MbBiReader *bir, void *userdata,
                            MbBiHeader *header)
{
    LokiReaderCtx *const ctx = static_cast<LokiReaderCtx *>(userdata);
    int ret;

    // A bid might not have been performed if the user forced a particular
    // format
    if (!ctx->have_loki_offset) {
        ret = find_loki_header(bir, &ctx->loki_hdr, &ctx->header_offset);
        if (ret < 0) {
            return ret;
        }
    }
    if (!ctx->have_header_offset) {
        ret = find_header(bir, &ctx->hdr, &ctx->header_offset);
        if (ret < 0) {
            return ret;
        }
    }

    // Get file size
    ret = mb_file_seek(bir->file, 0, SEEK_END, &ctx->file_size);
    if (ret < 0) {
        mb_bi_reader_set_error(bir, mb_file_error(bir->file),
                               "Failed to get file size: %s",
                               mb_file_error_string(bir->file));
        return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
    }

    // New-style images record the original values of changed fields in the
    // Android header
    if (ctx->loki_hdr.orig_kernel_size != 0
            && ctx->loki_hdr.orig_ramdisk_size != 0
            && ctx->loki_hdr.ramdisk_addr != 0) {
        return loki_read_new_header(bir, ctx, header);
    } else {
        return loki_read_old_header(bir, ctx, header);
    }

    // TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO














    char board_name[sizeof(ctx->hdr.name) + 1];
    char cmdline[sizeof(ctx->hdr.cmdline) + 1];

    strncpy(board_name, reinterpret_cast<char *>(ctx->hdr.name),
            sizeof(ctx->hdr.name));
    strncpy(cmdline, reinterpret_cast<char *>(ctx->hdr.cmdline),
            sizeof(ctx->hdr.cmdline));
    board_name[sizeof(ctx->hdr.name)] = '\0';
    cmdline[sizeof(ctx->hdr.cmdline)] = '\0';

    mb_bi_header_set_supported_fields(header, ANDROID_SUPPORTED_FIELDS);

    ret = mb_bi_header_set_board_name(header, board_name);
    if (ret != MB_BI_OK) return ret;

    ret = mb_bi_header_set_kernel_cmdline(header, cmdline);
    if (ret != MB_BI_OK) return ret;

    ret = mb_bi_header_set_page_size(header, ctx->hdr.page_size);
    if (ret != MB_BI_OK) return ret;

    ret = mb_bi_header_set_kernel_address(header, ctx->hdr.kernel_addr);
    if (ret != MB_BI_OK) return ret;

    ret = mb_bi_header_set_ramdisk_address(header, ctx->hdr.ramdisk_addr);
    if (ret != MB_BI_OK) return ret;

    ret = mb_bi_header_set_secondboot_address(header, ctx->hdr.second_addr);
    if (ret != MB_BI_OK) return ret;

    ret = mb_bi_header_set_kernel_tags_address(header, ctx->hdr.tags_addr);
    if (ret != MB_BI_OK) return ret;

    // TODO: unused
    // TODO: id

    // Calculate offsets for each section

    uint64_t pos = 0;
    uint32_t page_size = mb_bi_header_page_size(header);

    // pos cannot overflow due to the nature of the operands (adding UINT32_MAX
    // a few times can't overflow a uint64_t). File length overflow is checked
    // during read.

    // Header
    pos += ctx->header_offset;
    pos += sizeof(AndroidHeader);
    pos += align_page_size<uint64_t>(pos, page_size);

    // Kernel
    ctx->kernel_offset = pos;
    pos += ctx->hdr.kernel_size;
    pos += align_page_size<uint64_t>(pos, page_size);

    // Ramdisk
    ctx->ramdisk_offset = pos;
    pos += ctx->hdr.ramdisk_size;
    pos += align_page_size<uint64_t>(pos, page_size);

    // Second bootloader
    ctx->second_offset = pos;
    pos += ctx->hdr.second_size;
    pos += align_page_size<uint64_t>(pos, page_size);

    // Device tree
    ctx->dt_offset = pos;
    pos += ctx->hdr.dt_size;
    pos += align_page_size<uint64_t>(pos, page_size);

    return MB_BI_OK;
}

int android_reader_read_entry(MbBiReader *bir, void *userdata,
                              MbBiEntry *entry)
{
    AndroidReaderCtx *const ctx = static_cast<AndroidReaderCtx *>(userdata);

    // Advance to next entry
    android_reader_advance_state(ctx);

    uint64_t offset;
    uint64_t size;
    uint64_t type;
    int ret;

    switch (ctx->state) {
    case AndroidState::KERNEL:
        offset = ctx->kernel_offset;
        size = ctx->hdr.kernel_size;
        type = MB_BI_ENTRY_KERNEL;
        break;
    case AndroidState::RAMDISK:
        offset = ctx->ramdisk_offset;
        size = ctx->hdr.ramdisk_size;
        type = MB_BI_ENTRY_RAMDISK;
        break;
    case AndroidState::SECONDBOOT:
        offset = ctx->second_offset;
        size = ctx->hdr.second_size;
        type = MB_BI_ENTRY_SECONDBOOT;
        break;
    case AndroidState::DT:
        offset = ctx->dt_offset;
        size = ctx->hdr.dt_size;
        type = MB_BI_ENTRY_DEVICE_TREE;
        break;
    case AndroidState::END:
        return MB_BI_EOF;
    default:
        mb_bi_reader_set_error(bir, MB_BI_ERROR_INTERNAL_ERROR,
                               "Illegal state: %d",
                               static_cast<int>(ctx->state));
        return MB_BI_FATAL;
    }

    // Check truncation here instead of in android_reader_read_data() so we can
    // give the caller an accurate size value
    if (offset > ctx->file_size) {
        mb_bi_reader_set_error(bir, MB_BI_ERROR_FILE_FORMAT,
                               "Image offset exceeds file size "
                               "(expected %" PRIu64 " more bytes)",
                               ctx->read_end_offset - ctx->read_cur_offset);
        return MB_BI_FAILED;
    }

    if (size > ctx->file_size || offset > ctx->file_size - size) {
        // Except in the case of the DT image because some devices can (and do)
        // boot with a truncated image
        if (ctx->state != AndroidState::DT || !ctx->allow_truncated_dt) {
            mb_bi_reader_set_error(bir, MB_BI_ERROR_FILE_FORMAT,
                                   "Image is truncated "
                                   "(expected %" PRIu64 " more bytes)",
                                   ctx->read_end_offset - ctx->read_cur_offset);
            return MB_BI_FAILED;
        }

        size = ctx->file_size - offset;
    }

    bool need_seek = ctx->read_cur_offset != offset;

    // Integer overflow already checked in android_reader_read_header()
    ctx->read_start_offset = offset;
    ctx->read_end_offset = ctx->read_start_offset + size;
    ctx->read_cur_offset = ctx->read_start_offset;

    if (need_seek) {
        ret = mb_file_seek(bir->file, ctx->read_start_offset, SEEK_SET,
                           nullptr);
        if (ret < 0) {
            return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
        }
    }

    ret = mb_bi_entry_set_type(entry, type);
    if (ret != MB_BI_OK) return ret;

    ret = mb_bi_entry_set_size(entry, size);
    if (ret != MB_BI_OK) return ret;

    return MB_BI_OK;
}

int android_reader_read_data(MbBiReader *bir, void *userdata,
                             void *buf, size_t buf_size,
                             size_t *bytes_read)
{
    AndroidReaderCtx *const ctx = static_cast<AndroidReaderCtx *>(userdata);

    size_t to_copy = std::min<size_t>(
            buf_size, ctx->read_end_offset - ctx->read_cur_offset);

    int ret = _mb_bi_read_fully(bir->file, buf, to_copy, bytes_read);
    if (ret < 0) {
        mb_bi_reader_set_error(bir, mb_file_error(bir->file),
                               "Failed to read data: %s",
                               mb_file_error_string(bir->file));
        return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
    }

    if (ctx->read_cur_offset > SIZE_MAX - *bytes_read) {
        mb_bi_reader_set_error(bir, MB_BI_ERROR_FILE_FORMAT,
                               "Current offset %" PRIu64 " with read size %"
                               MB_PRIzu " would overflow integer",
                               ctx->read_cur_offset, *bytes_read);
        return MB_BI_FATAL;
    }

    ctx->read_cur_offset += *bytes_read;

    // Fail if we reach EOF early
    if (*bytes_read == 0 && ctx->read_cur_offset != ctx->read_end_offset) {
        mb_bi_reader_set_error(bir, MB_BI_ERROR_FILE_FORMAT,
                               "Image is truncated "
                               "(expected %" PRIu64 " more bytes)",
                               ctx->read_end_offset - ctx->read_cur_offset);
        return MB_BI_FATAL;
    }

    return *bytes_read == 0 ? MB_BI_EOF : MB_BI_OK;
}

int android_reader_free(MbBiReader *bir, void *userdata)
{
    (void) bir;
    AndroidReaderCtx *const ctx = static_cast<AndroidReaderCtx *>(userdata);
    free(ctx);
    return MB_BI_OK;
}

/*!
 * \brief Enable support for Android boot image format
 *
 * \param bir MbBiReader
 *
 * \return
 *   * #MB_BI_OK if the format is successfully enabled
 *   * #MB_BI_WARN if the format is already enabled
 *   * \<= #MB_BI_FAILED if an error occurs
 */
int mb_bi_reader_enable_format_android(MbBiReader *bir)
{
    AndroidReaderCtx *const ctx = static_cast<AndroidReaderCtx *>(
            calloc(1, sizeof(AndroidReaderCtx)));
    if (!ctx) {
        mb_bi_reader_set_error(bir, -errno,
                               "Failed to allocate AndroidReaderCtx: %s",
                               strerror(errno));
        return MB_BI_FAILED;
    }

    ctx->state = AndroidState::START;

    // Allow truncated dt image by default
    ctx->allow_truncated_dt = true;

    return _mb_bi_reader_register_format(bir,
                                         ctx,
                                         MB_BI_FORMAT_ANDROID,
                                         MB_BI_FORMAT_NAME_ANDROID,
                                         &android_reader_bid,
                                         &android_reader_set_option,
                                         &android_reader_read_header,
                                         &android_reader_read_entry,
                                         &android_reader_read_data,
                                         &android_reader_free);
}

MB_END_C_DECLS
