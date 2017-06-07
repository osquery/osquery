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

#include <osquery/system.h>

#include "osquery/carver/carver.h"
#include "osquery/filesystem/fileops.h"

namespace osquery {

Status compress(const boost::filesystem::path& in,
                const boost::filesystem::path& out) {
  PlatformFile archFile(in.string(), PF_OPEN_EXISTING | PF_READ);
  PlatformFile archCompress(out.string(), PF_CREATE_NEW | PF_WRITE);
  ZSTD_CStream* const cstream = ZSTD_createCStream();
  if (cstream == NULL) {
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
  size_t read, toRead = buffInSize;

  while ((read = archFile.read(buffIn.data(), toRead))) {
    ZSTD_inBuffer input = {buffIn.data(), read, 0};
    while (input.pos < input.size) {
      ZSTD_outBuffer output = {buffOut.data(), buffOutSize, 0};
      toRead = ZSTD_compressStream(cstream, &output, &input);
      if (ZSTD_isError(toRead)) {
        return Status(1,
                      "ZSTD_compressStream() error : " +
                          std::string(ZSTD_getErrorName(toRead)));
      }
      if (toRead > buffInSize) {
        toRead = buffInSize;
      }
      archCompress.seek(0, PF_SEEK_END);
      archCompress.write(buffOut.data(), output.pos);
    }
  }

  ZSTD_outBuffer output = {buffOut.data(), buffOutSize, 0};
  size_t const remainingToFlush = ZSTD_endStream(cstream, &output);

  if (remainingToFlush) {
    return Status(1, "Couldn't fully flush compressed file");
  }

  archCompress.seek(0, PF_SEEK_END);
  archCompress.write(buffOut.data(), output.pos);
  ZSTD_freeCStream(cstream);

  return Status(0);
}

Status decompress(const boost::filesystem::path& in,
                  const boost::filesystem::path& out) {
  PlatformFile inFile(in.string(), PF_OPEN_EXISTING | PF_READ);
  PlatformFile outFile(out.string(), PF_CREATE_NEW | PF_WRITE);
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
    return Status(1,
                  "ZSTD_initDStream() error : " +
                      std::string(ZSTD_getErrorName(initResult)));
  }
  size_t read, toRead = initResult;
  while ((read = inFile.read(buffIn.data(), toRead))) {
    ZSTD_inBuffer input = {buffIn.data(), read, 0};
    while (input.pos < input.size) {
      ZSTD_outBuffer output = {buffOut.data(), buffOutSize, 0};
      toRead = ZSTD_decompressStream(dstream, &output, &input);
      if (ZSTD_isError(toRead)) {
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
  auto ret = archive_write_open_filename(arch, out.c_str());
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

    // TODO: Chunking or a max file size.
    std::ifstream in(f.string(), std::ios::binary);
    std::stringstream buffer;
    buffer << in.rdbuf();
    archive_write_data(arch, buffer.str().c_str(), buffer.str().size());
    in.close();
    archive_entry_free(entry);
  }
  archive_write_free(arch);

  return Status(0, "Ok");
};
} // namespace osquery
