/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cstring>
#include <string>

#include <zlib.h>

namespace osquery {

#define MOD_GZIP_ZLIB_WINDOWSIZE 15
#define MOD_GZIP_ZLIB_CFACTOR 9

std::string compressString(const std::string& data) {
  z_stream zs;
  memset(&zs, 0, sizeof(zs));

  if (deflateInit2(&zs,
                   Z_BEST_COMPRESSION,
                   Z_DEFLATED,
                   MOD_GZIP_ZLIB_WINDOWSIZE + 16,
                   MOD_GZIP_ZLIB_CFACTOR,
                   Z_DEFAULT_STRATEGY) != Z_OK) {
    return std::string();
  }

  zs.next_in = (Bytef*)data.data();
  zs.avail_in = static_cast<uInt>(data.size());

  int ret = Z_OK;
  std::string output;

  {
    char buffer[16384] = {0};
    while (ret == Z_OK) {
      zs.next_out = reinterpret_cast<Bytef*>(buffer);
      zs.avail_out = sizeof(buffer);

      ret = deflate(&zs, Z_FINISH);
      if (output.size() < zs.total_out) {
        output.append(buffer, zs.total_out - output.size());
      }
    }
  }

  deflateEnd(&zs);
  if (ret != Z_STREAM_END) {
    return std::string();
  }

  return output;
}
}
