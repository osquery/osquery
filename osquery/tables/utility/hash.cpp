/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/filesystem.hpp>

#include <osquery/filesystem.h>
#include <osquery/hash.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData genHash(QueryContext& context) {
  QueryData results;

  auto paths = context.constraints["path"].getAll(EQUALS);
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path)) {
      continue;
    }

    Row r;
    r["path"]       = path.string();
    r["directory"]  = path.parent_path().string();
    r["md5"] = osquery::hashFromFile(HASH_TYPE_MD5, path.string());
    r["sha1"] = osquery::hashFromFile(HASH_TYPE_SHA1, path.string());
    r["sha256"] = osquery::hashFromFile(HASH_TYPE_SHA256, path.string());
    results.push_back(r);
  }

  auto directories = context.constraints["directory"].getAll(EQUALS);
  for (const auto& directory_string : directories) {
    boost::filesystem::path directory = directory_string;
    if (!boost::filesystem::is_directory(directory)) {
      continue;
    }

    // Iterate over the directory and generate a hash for each regular file.
    boost::filesystem::directory_iterator begin(directory), end;
    for (; begin != end; ++begin) {
      Row r;
      r["path"] = begin->path().string();
      r["directory"] = directory_string;
      if (boost::filesystem::is_regular_file(begin->status())) {
        r["md5"] = osquery::hashFromFile(HASH_TYPE_MD5, begin->path().string());
        r["sha1"] =
            osquery::hashFromFile(HASH_TYPE_SHA1, begin->path().string());
        r["sha256"] =
            osquery::hashFromFile(HASH_TYPE_SHA256, begin->path().string());
      }
      results.push_back(r);
    }
  }

  return results;
}
}
}
