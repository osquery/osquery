/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sys/stat.h>

#include <boost/filesystem.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

void genFileInfo(const std::string& path,
                 const std::string& filename,
                 const std::string& dir,
                 const std::string& pattern,
                 QueryData& results) {
  // Must provide the path, filename, directory separate from boost path->string
  // helpers to match any explicit (query-parsed) predicate constraints.
  struct stat file_stat, link_stat;
  if (lstat(path.c_str(), &link_stat) < 0 || stat(path.c_str(), &file_stat)) {
    // Path was not real, had too may links, or could not be accessed.
    return;
  }

  Row r;
  r["path"] = path;
  r["filename"] = filename;
  r["directory"] = dir;

  r["inode"] = BIGINT(file_stat.st_ino);
  r["uid"] = BIGINT(file_stat.st_uid);
  r["gid"] = BIGINT(file_stat.st_gid);
  r["mode"] = lsperms(file_stat.st_mode);
  r["device"] = BIGINT(file_stat.st_rdev);
  r["size"] = BIGINT(file_stat.st_size);
  r["block_size"] = INTEGER(file_stat.st_blksize);
  r["hard_links"] = INTEGER(file_stat.st_nlink);

  // Times
  r["atime"] = BIGINT(file_stat.st_atime);
  r["mtime"] = BIGINT(file_stat.st_mtime);
  r["ctime"] = BIGINT(file_stat.st_ctime);

  // Type booleans
  r["is_file"] = (!S_ISDIR(file_stat.st_mode)) ? "1" : "0";
  r["is_dir"] = (S_ISDIR(file_stat.st_mode)) ? "1" : "0";
  r["is_link"] = (S_ISLNK(link_stat.st_mode)) ? "1" : "0";
  r["is_char"] = (S_ISCHR(file_stat.st_mode)) ? "1" : "0";
  r["is_block"] = (S_ISBLK(file_stat.st_mode)) ? "1" : "0";

  // pattern
  r["pattern"] = pattern;

  results.push_back(r);
}

QueryData genFile(QueryContext& context) {
  QueryData results;

  auto paths = context.constraints["path"].getAll(EQUALS);
  for (const auto& path_string : paths) {
    if (!isReadable(path_string)) {
      continue;
    }

    fs::path path = path_string;
    genFileInfo(path_string,
                path.filename().string(),
                path.parent_path().string(),
                "",
                results);
  }

  // Now loop through constraints using the directory column constraint.
  auto directories = context.constraints["directory"].getAll(EQUALS);
  for (const auto& directory_string : directories) {
    if (!isReadable(directory_string) || !isDirectory(directory_string)) {
      continue;
    }

    try {
      // Iterate over the directory and generate info for each regular file.
      fs::directory_iterator begin(directory_string), end;
      for (; begin != end; ++begin) {
        genFileInfo(begin->path().string(),
                    begin->path().filename().string(),
                    directory_string,
                    "",
                    results);
      }
    } catch (const fs::filesystem_error& e) {
      continue;
    }
  }

  // Now loop through contraints using the pattern column constraint.
  auto patterns = context.constraints["pattern"].getAll(EQUALS);
  if (patterns.size() != 1) {
    return results;
  }

  for (const auto& pattern : patterns) {
    std::vector<std::string> expanded_patterns;
    auto status = resolveFilePattern(pattern, expanded_patterns);
    if (!status.ok()) {
      VLOG(1) << "Could not expand pattern properly: " << status.toString();
      return results;
    }

    for (const auto& resolved : expanded_patterns) {
      if (!isReadable(resolved)) {
        continue;
      }
      fs::path path = resolved;
      genFileInfo(resolved,
                  path.filename().string(),
                  path.parent_path().string(),
                  pattern,
                  results);

    }
  }

  return results;
}
}
}
