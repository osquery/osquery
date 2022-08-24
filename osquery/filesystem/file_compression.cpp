/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/system.h>

// This define is required for Windows static linking of libarchive
#define LIBARCHIVE_STATIC
#include <archive.h>
#include <archive_entry.h>
#include <zstd.h>

#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/filesystem/filesystem.h>

namespace osquery {

Status compress(const boost::filesystem::path& in,
                const boost::filesystem::path& out) {
  PlatformFile inFile(in, PF_OPEN_EXISTING | PF_READ);
  if (!inFile.isValid()) {
    return Status::failure("Could not open in file: " + in.string() +
                           " for compression");
  }

  PlatformFile outFile(out, PF_CREATE_ALWAYS | PF_WRITE);
  if (!outFile.isValid()) {
    return Status::failure("Could not open out file: " + out.string() +
                           " for compression");
  }

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
  PlatformFile inFile(in, PF_OPEN_EXISTING | PF_READ);
  if (!inFile.isValid()) {
    return Status::failure("Could not open in file: " + in.string() +
                           " for decompression");
  }

  PlatformFile outFile(out, PF_CREATE_ALWAYS | PF_WRITE);
  if (!outFile.isValid()) {
    return Status::failure("Could not open in file: " + in.string() +
                           " for decompression");
  }

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
               const boost::filesystem::path& out,
               std::size_t block_size) {
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
    PlatformFile pFile(f, PF_OPEN_EXISTING | PF_READ);

    auto entry = archive_entry_new();
    archive_entry_set_pathname(entry, f.string().c_str());
    archive_entry_set_size(entry, pFile.size());
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0644);
    archive_write_header(arch, entry);

    auto blkCount = static_cast<size_t>(ceil(static_cast<double>(pFile.size()) /
                                             static_cast<double>(block_size)));
    for (size_t i = 0; i < blkCount; i++) {
      std::vector<char> block(block_size, 0);
      auto r = pFile.read(block.data(), block_size);
      if (r > 0 && static_cast<std::size_t>(r) != block_size) {
        // resize the buffer to size we read as last block is likely smaller
        block.resize(static_cast<std::size_t>(r));
      }
      archive_write_data(arch, block.data(), block.size());
    }
    archive_entry_free(entry);
  }
  archive_write_free(arch);
  return Status::success();
};
} // namespace osquery
