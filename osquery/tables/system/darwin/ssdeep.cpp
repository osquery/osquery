/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "osquery/tables/system/darwin/ssdeep.h"

#include <boost/filesystem.hpp>
#include <fuzzy.h>
#include <osquery/filesystem.h>
#include <stdio.h>
#include <stdlib.h>

namespace osquery {
namespace tables {

void expandFSPathConstraints(QueryContext& context,
                             std::string path_column_name,
                             std::set<std::string>& paths) {
  context.expandConstraints(
    "path",
    LIKE,
    paths,
    ([&](const std::string& pattern, std::set<std::string>& out) {
      std::vector<std::string> patterns;
      auto status =
        resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
      if (status.ok()) {
        for (const auto& resolved : patterns) {
          out.insert(resolved);
        }
      }
      return status;
    }));
}

void genSsdeepForFile(const std::string& path,
                      const std::string& dir,
                      QueryData& results) {
  auto fd = fopen(path.c_str(), "r");
  char *file_ssdeep_c_str = (char *)malloc(FUZZY_MAX_RESULT);
  fuzzy_hash_file(fd, file_ssdeep_c_str);
  std::string file_ssdeep(file_ssdeep_c_str);
  delete file_ssdeep_c_str;

  Row r;
  r["path"] = path;
  r["directory"] = dir;
  r["ssdeep"] = std::move(file_ssdeep);
  results.push_back(r);
}

QueryData genSsdeep(QueryContext& context) {
  QueryData results;
  boost::system::error_code ec;

  // The query must provide a predicate with constraints including path or
  // directory. We search for the parsed predicate constraints with the equals
  // operator.
  auto paths = context.constraints["path"].getAll(EQUALS);
  expandFSPathConstraints(context, "path", paths);
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path, ec)) {
      continue;
    }

    genSsdeepForFile(path_string, path.parent_path().string(), results);
  }

  auto directories = context.constraints["directory"].getAll(EQUALS);
  expandFSPathConstraints(context, "directory", directories);

  // Iterate over the directory paths
  for (const auto& directory_string : directories) {
    boost::filesystem::path directory = directory_string;
    if (!boost::filesystem::is_directory(directory, ec)) {
      continue;
    }

    // Iterate over the directory files and generate a hash for each regular
    // file.
    boost::filesystem::directory_iterator begin(directory), end;
    for (; begin != end; ++begin) {
      if (boost::filesystem::is_regular_file(begin->path(), ec)) {
        genSsdeepForFile(begin->path().string(), directory_string, results);
      }
    }
  }

  return results;
}

}
}
