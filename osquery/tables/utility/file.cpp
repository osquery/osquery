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

#include <osquery/tables.h>
#include <osquery/filesystem.h>

namespace osquery {
namespace tables {

void genFileInfo(const std::string& path,
                 const std::string& filename,
                 const std::string& dir,
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

  results.push_back(r);
}

QueryData genFile(QueryContext& context) {
  QueryData results;

  auto paths = context.constraints["path"].getAll(EQUALS);
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    genFileInfo(path_string,
                path.filename().string(),
                path.parent_path().string(),
                results);
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
      genFileInfo(begin->path().string(),
                  begin->path().filename().string(),
                  directory_string,
                  results);
    }
  }

  return results;
}
}
}
