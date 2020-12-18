/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/sql/sql.h>

#include <osquery/hashing/hashing.h>
#include <osquery/tables/events/event_utils.h>

namespace osquery {

const std::set<std::string> kCommonFileColumns = {
    "inode", "uid", "gid", "mode", "size", "atime", "mtime", "ctime",
};

void decorateFileEvent(const std::string& path, bool hash, Row& r) {
  auto results = SQL::selectAllFrom("file", "path", EQUALS, path);
  if (results.size() == 1) {
    auto& row = results.at(0);
    for (const auto& key : kCommonFileColumns) {
      if (row.count(key) > 0) {
        r[key] = row.at(key);
      }
    }
  }

  if (hash) {
    auto hashes = hashMultiFromFile(
        HASH_TYPE_MD5 | HASH_TYPE_SHA1 | HASH_TYPE_SHA256, path);
    r["md5"] = std::move(hashes.md5);
    r["sha1"] = std::move(hashes.sha1);
    r["sha256"] = std::move(hashes.sha256);
    // Hashed determines the success/status of hashing, -1 failed, 1 success.
    r["hashed"] = (r.at("md5").empty()) ? "-1" : "1";
  } else {
    // Alternatively if hashing wasn't needed hashed is a 0.
    r["hashed"] = "0";
  }
}
}
