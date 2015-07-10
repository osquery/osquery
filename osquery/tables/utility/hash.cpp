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

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

void genHashForFile(const std::string& path,
                    const std::string& dir,
                    QueryData& results) {
  // Must provide the path, filename, directory separate from boost path->string
  // helpers to match any explicit (query-parsed) predicate constraints.
  Row r;
  r["path"] = path;
  r["directory"] = dir;
  r["md5"] = osquery::hashFromFile(HASH_TYPE_MD5, path);
  r["sha1"] = osquery::hashFromFile(HASH_TYPE_SHA1, path);
  r["sha256"] = osquery::hashFromFile(HASH_TYPE_SHA256, path);
  results.push_back(r);
}

QueryData genHash(QueryContext& context) {
  QueryData results;

  // The query must provide a predicate with constraints including path or
  // directory. We search for the parsed predicate constraints with the equals
  // operator.
  auto paths = context.constraints["path"].getAll(EQUALS);
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path)) {
      continue;
    }

    genHashForFile(path_string, path.parent_path().string(), results);
  }

  // Now loop through constraints using the directory column constraint.
  auto directories = context.constraints["directory"].getAll(EQUALS);
  for (const auto& directory_string : directories) {
    boost::filesystem::path directory = directory_string;
    if (!boost::filesystem::is_directory(directory)) {
      continue;
    }

    // Iterate over the directory and generate a hash for each regular file.
    boost::filesystem::directory_iterator begin(directory), end;
    for (; begin != end; ++begin) {
      if (boost::filesystem::is_regular_file(begin->status())) {
        genHashForFile(begin->path().string(), directory_string, results);
      }
    }
  }

  return results;
}
}
}
