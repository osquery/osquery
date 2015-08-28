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

QueryData genMagicData(QueryContext& context) {
  QueryData results;
  magic_t magic_cookie = nullptr;

  // No default flags
  magic_cookie = magic_open(MAGIC_NONE);

  if (magic_cookie == nullptr) {
    VLOG(1) << "Unable to initialize magic library";
    return results;
  }
  if (magic_load(magic_cookie, nullptr) != 0) {
    VLOG(1) << "Unable to load magic database : " << magic_error(magic_cookie);
    magic_close(magic_cookie);
    return results;
  }

  // Iterate through all the provided paths
  auto paths = context.constraints["path"].getAll(EQUALS);
  for (const auto& path_string : paths) {
    Row r;
    r["path"] = path_string;
    r["data"] = magic_file(magic_cookie, path_string.c_str());

    // Retrieve MIME type
    magic_setflags(magic_cookie, MAGIC_MIME_TYPE);
    r["mime_type"] = magic_file(magic_cookie, path_string.c_str());

    // Retrieve MIME encoding
    magic_setflags(magic_cookie, MAGIC_MIME_ENCODING);
    r["mime_encoding"] = magic_file(magic_cookie, path_string.c_str());

    results.push_back(r);
  }

  magic_close(magic_cookie);
  return results;
}
}
}
