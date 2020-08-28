/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <magic.h>

#include <numeric>
#include <vector>

#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem.hpp>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

namespace osquery {
namespace tables {

namespace {

const std::vector<std::string> kMagicFiles = {
    "/usr/share/file/magic.mgc",
    "/usr/share/misc/magic.mgc",
};

constexpr char const* kMagicFileDBSep = ":";
} // namespace

QueryData genMagicData(QueryContext& context) {
  QueryData results;

  // No default flags
  magic_t magic_cookie = magic_open(MAGIC_NONE);
  if (magic_cookie == nullptr) {
    VLOG(1) << "Unable to initialize magic library";
    return results;
  }

  std::string magic_db_files;
  if (context.hasConstraint("magic_db_files")) {
    auto magic_files = context.constraints["magic_db_files"].getAll(EQUALS);
    magic_db_files = boost::algorithm::join(magic_files, kMagicFileDBSep);
  } else {
    magic_db_files = boost::algorithm::join(kMagicFiles, kMagicFileDBSep);
  }

  if (magic_load(magic_cookie, magic_db_files.c_str()) != 0) {
    LOG(WARNING) << "Unable to load magic list of database: " << magic_db_files
                 << " because: " << magic_error(magic_cookie);
    magic_close(magic_cookie);
    return results;
  }

  // Iterate through all the provided paths
  auto paths = context.constraints["path"].getAll(EQUALS);
  for (const auto& path_string : paths) {
    Row r;
    r["path"] = path_string;
    r["magic_db_files"] = magic_db_files;

    auto data = magic_file(magic_cookie, path_string.c_str());
    if (data != nullptr) {
      r["data"] = data;
    }

    // Retrieve MIME type
    magic_setflags(magic_cookie, MAGIC_MIME_TYPE);
    auto mime_type = magic_file(magic_cookie, path_string.c_str());
    if (mime_type != nullptr) {
      r["mime_type"] = mime_type;
    }

    // Retrieve MIME encoding
    magic_setflags(magic_cookie, MAGIC_MIME_ENCODING);
    auto mime_encoding = magic_file(magic_cookie, path_string.c_str());
    if (mime_encoding != nullptr) {
      r["mime_encoding"] = mime_encoding;
    }

    results.push_back(r);
  }

  magic_close(magic_cookie);
  return results;
}
} // namespace tables
} // namespace osquery
