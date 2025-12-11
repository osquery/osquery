/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <zlib.h>

namespace osquery {

// zlib documentation states to add 16 to the window size to enable gzip
#define MOD_GZIP_ZLIB_WINDOWSIZE (MAX_WBITS + 16)
#define MOD_GZIP_ZLIB_CFACTOR 9
// This buffer size seems to have been adapted in our original code from the
// zlib example https://zlib.net/zpipe.c
#define BUFSIZE 16384

std::string compressString(const std::string& data) {
  z_stream zs{};
  if (deflateInit2(&zs,
                   Z_BEST_COMPRESSION,
                   Z_DEFLATED,
                   MOD_GZIP_ZLIB_WINDOWSIZE,
                   MOD_GZIP_ZLIB_CFACTOR,
                   Z_DEFAULT_STRATEGY) != Z_OK) {
    return std::string();
  }

  zs.next_in = (Bytef*)data.data();
  zs.avail_in = static_cast<uInt>(data.size());

  int ret = Z_OK;
  std::string output;
  char buffer[BUFSIZE] = {0};
  while (ret == Z_OK) {
    zs.next_out = reinterpret_cast<Bytef*>(buffer);
    zs.avail_out = sizeof(buffer);

    ret = deflate(&zs, Z_FINISH);
    output.append(buffer, sizeof(buffer) - zs.avail_out);
  }

  deflateEnd(&zs);
  if (ret != Z_STREAM_END) {
    return std::string();
  }

  return output;
}

std::string decompressString(const std::string& data) {
  z_stream zs{};
  if (inflateInit2(&zs, MOD_GZIP_ZLIB_WINDOWSIZE) != Z_OK) {
    return std::string();
  }
  zs.next_in = (Bytef*)data.data();
  zs.avail_in = static_cast<uInt>(data.size());

  int ret = Z_OK;
  std::string output;
  char buffer[BUFSIZE] = {0};
  while (ret == Z_OK) {
    zs.next_out = reinterpret_cast<Bytef*>(buffer);
    zs.avail_out = sizeof(buffer);

    ret = inflate(&zs, Z_NO_FLUSH);
    output.append(buffer, sizeof(buffer) - zs.avail_out);
  }

  inflateEnd(&zs);
  if (ret != Z_STREAM_END) {
    return std::string();
  }

  return output;
}
} // namespace osquery
