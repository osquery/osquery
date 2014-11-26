// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core/md5.h"

#include <boost/filesystem.hpp>

#include "osquery/tables.h"
#include "osquery/filesystem.h"

namespace osquery {
namespace tables {

QueryData genHash(QueryContext& context) {
  QueryData results;
  osquery::md5::MD5 digest;

  auto paths = context.constraints["path"].getAll(EQUALS);
  for (const auto& path_string : paths) {
      boost::filesystem::path path = path_string;
      if (!boost::filesystem::is_regular_file(path)) {
        continue;
      }
      Row r;
      r["path"] = path.string();
      r["md5"] = std::string(digest.digestFile(path.c_str()));
      r["directory"] = path.parent_path().string();
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
        r["md5"] = digest.digestFile(begin->path().string().c_str());
      }
      results.push_back(r);
    }
  }

  return results;
}
}
}
