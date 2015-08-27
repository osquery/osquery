/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <stdio.h>
#include <magic.h>

#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

static int getMagicData(const int magic_flag, const std::string file_path, std::string &magic_data) {
  magic_t magic_cookie;

  magic_cookie = magic_open(magic_flag);

  if (!magic_cookie) {
    VLOG(1) << "Unable to initialize magic library.";
    return 1;
  }
  if (magic_load(magic_cookie, nullptr) != 0) {
    VLOG(1) << "Unable to load magic database - " << magic_error(magic_cookie);
    magic_close(magic_cookie);
    return 1;
  }
  magic_data = magic_file(magic_cookie, file_path.c_str());
  magic_close(magic_cookie);

  return 0;
}

QueryData genMagicData(QueryContext& context) {
  QueryData results;

  // Iterate through all the provided paths
  auto paths = context.constraints["path"].getAll(EQUALS);
  for (const auto& path_string : paths) {
    Row r;
    r["path"] = path_string;

    // Retrieve data with no flags
    if (getMagicData(MAGIC_NONE, path_string, r["data"]) != 0) {
      return results;
    }

    // Retrieve MIME type
    if (getMagicData(MAGIC_MIME_TYPE, path_string, r["mime_type"]) != 0) {
      return results;
    }

    // Retrieve MIME encoding
    if (getMagicData(MAGIC_MIME_ENCODING, path_string, r["mime_encoding"]) != 0) {
      return results;
    }

    results.push_back(r);
  }

  return results;
}
}
}
