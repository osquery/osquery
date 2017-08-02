/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#ifdef WIN32
#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

// This define is required for Windows static linking of libarchive
#define LIBARCHIVE_STATIC
#include <archive.h>
#include <archive_entry.h>
#include <zstd.h>

#include <osquery/flags.h>
#include <osquery/system.h>

#include "osquery/carver/carver.h"
#include "osquery/filesystem/fileops.h"

namespace osquery {

DECLARE_uint32(carver_block_size);

Status compress(const boost::filesystem::path& in,
                const boost::filesystem::path& out) {
  PlatformFile inFile(in.string(), PF_OPEN_EXISTING | PF_READ);
  PlatformFile outFile(out.string(), PF_CREATE_NEW | PF_WRITE);

  auto inFileSize = inFile.size();
  ZSTD_CStream* const cstream = ZSTD_createCStream();
  if (cstream == nullptr) {
    return Status(1, "Couldn't create compression stream");
  }

  size_t const initResult = ZSTD_initCStream(cstream, 1);
  if (ZSTD_isError(initResult)) {
    return Status(1, "Couldn't initialize compression stream");
  }

  size_t const buffInSize = ZSTD_CStreamInSize();
  size_t const buffOutSize = ZSTD_CStreamOutSize();
  std::vector<void*> buffIn(buffInSize);
  std::vector<void*> buffOut(buffOutSize);
  auto read = buffInSize;
  auto toRead = buffInSize;
  size_t readSoFar = 0;
  while (true) {
    read = inFile.read(buffIn.data(), toRead);
    if (read < 1) {
      break;
    }
    readSoFar += read;
    if (readSoFar > inFileSize) {
      ZSTD_freeCStream(cstream);
      return Status(1, "File changed during compression");
    }

    ZSTD_inBuffer input = {buffIn.data(), read, 0};
    while (input.pos < input.size) {
      ZSTD_outBuffer output = {buffOut.data(), buffOutSize, 0};
      toRead = ZSTD_compressStream(cstream, &output, &input);
      if (ZSTD_isError(toRead)) {
        ZSTD_freeCStream(cstream);
        return Status(1,
                      "ZSTD_compressStream() error : " +
                          std::string(ZSTD_getErrorName(toRead)));
      }
      if (toRead > buffInSize) {
        toRead = buffInSize;
      }
      outFile.seek(0, PF_SEEK_END);
      outFile.write(buffOut.data(), output.pos);
    }
  }

  ZSTD_outBuffer output = {buffOut.data(), buffOutSize, 0};
  size_t const remainingToFlush = ZSTD_endStream(cstream, &output);

  if (remainingToFlush) {
    ZSTD_freeCStream(cstream);
    return Status(1, "Couldn't fully flush compressed file");
  }

  outFile.seek(0, PF_SEEK_END);
  outFile.write(buffOut.data(), output.pos);
  ZSTD_freeCStream(cstream);

  return Status(0);
}

Status decompress(const boost::filesystem::path& in,
                  const boost::filesystem::path& out) {
  PlatformFile inFile(in.string(), PF_OPEN_EXISTING | PF_READ);
  PlatformFile outFile(out.string(), PF_CREATE_NEW | PF_WRITE);

  auto inFileSize = inFile.size();
  size_t const buffInSize = ZSTD_DStreamInSize();
  size_t const buffOutSize = ZSTD_DStreamOutSize();
  std::vector<void*> buffIn(buffInSize);
  std::vector<void*> buffOut(buffOutSize);

  ZSTD_DStream* const dstream = ZSTD_createDStream();
  if (dstream == NULL) {
    return Status(1, "ZSTD_createDStream() error");
  }

  size_t const initResult = ZSTD_initDStream(dstream);
  if (ZSTD_isError(initResult)) {
    ZSTD_freeDStream(dstream);
    return Status(1,
                  "ZSTD_initDStream() error : " +
                      std::string(ZSTD_getErrorName(initResult)));
  }
  auto read = initResult;
  auto toRead = initResult;
  size_t readSoFar = 0;
  while (true) {
    read = inFile.read(buffIn.data(), toRead);
    if (read < 1) {
      break;
    }
    readSoFar += read;
    if (readSoFar > inFileSize) {
      ZSTD_freeDStream(dstream);
      return Status(1, "File changed during decompression");
    }

    ZSTD_inBuffer input = {buffIn.data(), read, 0};
    while (input.pos < input.size) {
      ZSTD_outBuffer output = {buffOut.data(), buffOutSize, 0};
      toRead = ZSTD_decompressStream(dstream, &output, &input);
      if (ZSTD_isError(toRead)) {
        ZSTD_freeDStream(dstream);
        return Status(1,
                      "ZSTD_decompressStream() error : " +
                          std::string(ZSTD_getErrorName(toRead)));
      }
      outFile.seek(0, PF_SEEK_END);
      outFile.write(buffOut.data(), output.pos);
    }
  }
  ZSTD_freeDStream(dstream);
  return Status(0);
}

Status archive(const std::set<boost::filesystem::path>& paths,
               const boost::filesystem::path& out) {
  auto arch = archive_write_new();
  if (arch == nullptr) {
    return Status(1, "Failed to create tar archive");
  }
  archive_write_set_format_pax_restricted(arch);
  auto ret = archive_write_open_filename(arch, out.string().c_str());
  if (ret == ARCHIVE_FATAL) {
    archive_write_free(arch);
    return Status(1, "Failed to open tar archive for writing");
  }
  for (const auto& f : paths) {
    PlatformFile pFile(f.string(), PF_OPEN_EXISTING | PF_READ);

    auto entry = archive_entry_new();
    archive_entry_set_pathname(entry, f.leaf().string().c_str());
    archive_entry_set_size(entry, pFile.size());
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0644);
    archive_write_header(arch, entry);

    auto blockSize =
        FLAGS_carver_block_size > 0 ? FLAGS_carver_block_size : 8192;
    auto blkCount = static_cast<size_t>(ceil(static_cast<double>(pFile.size()) /
                                             static_cast<double>(blockSize)));
    for (size_t i = 0; i < blkCount; i++) {
      std::vector<char> block(blockSize, 0);
      auto r = pFile.read(block.data(), blockSize);
      if (r != blockSize && r > 0) {
        // resize the buffer to size we read as last block is likely smaller
        block.resize(r);
      }
      archive_write_data(arch, block.data(), block.size());
    }
    archive_entry_free(entry);
  }
  archive_write_free(arch);
  return Status(0, "Ok");
};
} // namespace osquery
