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

inline std::string lsperms(int mode) {
  static const char rwx[] = {'0', '1', '2', '3', '4', '5', '6', '7'};
  std::string bits;

  bits += rwx[(mode >> 9) & 7];
  bits += rwx[(mode >> 6) & 7];
  bits += rwx[(mode >> 3) & 7];
  bits += rwx[(mode >> 0) & 7];
  return bits;
}

QueryData genFile(QueryContext& context) {
  QueryData results;

  auto paths = context.constraints["path"].getAll(EQUALS);
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;

    Row r;
    r["path"] = path.string();
    r["filename"] = path.filename().string();

    struct stat file_stat, link_stat;
    if (lstat(path.string().c_str(), &link_stat) < 0 ||
        stat(path.string().c_str(), &file_stat)) {
      // Path was not real, had too may links, or could not be accessed.
      continue;
    }

    r["inode"] = BIGINT(file_stat.st_ino);
    r["uid"] = BIGINT(file_stat.st_uid);
    r["gid"] = BIGINT(file_stat.st_gid);
    r["mode"] = std::string(lsperms(file_stat.st_mode));
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

  return results;
}
}
}
