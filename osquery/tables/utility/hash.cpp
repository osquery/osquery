/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/hash.h>

#include <boost/filesystem.hpp>

#include <osquery/tables.h>
#include <osquery/filesystem.h>

namespace osquery {
namespace tables {

void computeAllHashes(Row& r, const std::string& content, long filelen){
    r["md5"]        = computeMD5(   (unsigned char *)content.c_str(), filelen);
    r["sha1"]       = computeSHA1(  (unsigned char *)content.c_str(), filelen);
    r["sha256"]     = computeSHA256((unsigned char *)content.c_str(), filelen);
}

QueryData genHash(QueryContext& context) {
  QueryData results;

  auto paths = context.constraints["path"].getAll(EQUALS);
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path)) {
      continue;
    }
    std::string content;
    auto s = osquery::readFile(path.string(), content);
    long filelen = (long)content.length();
    Row r;
    r["path"]       = path.string();
    r["directory"]  = path.parent_path().string();
    computeAllHashes(r, content, filelen);
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
        std::string content;
        auto s = osquery::readFile(begin->path().string(), content);
        computeAllHashes(r, content, content.length());
      }
      results.push_back(r);
    }
  }

  return results;
}
}
}
