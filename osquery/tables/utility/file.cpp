/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#if !defined(WIN32)
#include <sys/stat.h>
#endif

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/fileops.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>
#include <string>

#include <iostream>
namespace fs = boost::filesystem;

namespace osquery {

namespace tables {

#if !defined(WIN32)

const std::map<fs::file_type, std::string> kTypeNames{
    {fs::regular_file, "regular"},
    {fs::directory_file, "directory"},
    {fs::symlink_file, "symlink"},
    {fs::block_file, "block"},
    {fs::character_file, "character"},
    {fs::fifo_file, "fifo"},
    {fs::socket_file, "socket"},
    {fs::type_unknown, "unknown"},
    {fs::status_error, "error"},
};

#endif

void genFileInfo(const fs::path& path,
                 const fs::path& parent,
                 const std::string& pattern,
                 const std::string& start_path,
                 const int& limit,
                 QueryData& results) {
  // Must provide the path, filename, directory separate from boost path->string
  // helpers to match any explicit (query-parsed) predicate constraints.

  Row r;
  r["path"] = path.string();
  r["filename"] = path.filename().string();
  r["directory"] = parent.string();
  r["symlink"] = "0";
  r["start_path"] = SQL_TEXT(start_path);
  r["path_limit"] = INTEGER(limit);

#if !defined(WIN32)

  struct stat file_stat;

  // On POSIX systems, first check the link state.
  struct stat link_stat;
  if (lstat(path.string().c_str(), &link_stat) < 0) {
    // Path was not real, had too may links, or could not be accessed.
    return;
  }
  if (S_ISLNK(link_stat.st_mode)) {
    r["symlink"] = "1";
  }

  if (stat(path.string().c_str(), &file_stat)) {
    file_stat = link_stat;
  }

  r["inode"] = BIGINT(file_stat.st_ino);
  r["uid"] = BIGINT(file_stat.st_uid);
  r["gid"] = BIGINT(file_stat.st_gid);
  r["mode"] = lsperms(file_stat.st_mode);
  r["device"] = BIGINT(file_stat.st_rdev);
  r["size"] = BIGINT(file_stat.st_size);
  r["block_size"] = INTEGER(file_stat.st_blksize);
  r["hard_links"] = INTEGER(file_stat.st_nlink);

  r["atime"] = BIGINT(file_stat.st_atime);
  r["mtime"] = BIGINT(file_stat.st_mtime);
  r["ctime"] = BIGINT(file_stat.st_ctime);

#if defined(__linux__)
  // No 'birth' or create time in Linux or Windows.
  r["btime"] = "0";
  r["pid_with_namespace"] = "0";
#else
  r["btime"] = BIGINT(file_stat.st_birthtimespec.tv_sec);
#endif

  // Type booleans
  boost::system::error_code ec;
  auto status = fs::status(path, ec);
  if (kTypeNames.count(status.type())) {
    r["type"] = kTypeNames.at(status.type());
  } else {
    r["type"] = "unknown";
  }

#if defined(__APPLE__)
  std::string bsd_file_flags_description;
  if (!describeBSDFileFlags(bsd_file_flags_description, file_stat.st_flags)) {
    VLOG(1)
        << "The following file had undocumented BSD file flags (chflags) set: "
        << path;
  }

  r["bsd_flags"] = bsd_file_flags_description;
#endif

#else

  WINDOWS_STAT file_stat;

  auto rtn = platformStat(path, &file_stat);
  if (!rtn.ok()) {
    VLOG(1) << "PlatformStat failed with " << rtn.getMessage();
    return;
  }

  r["symlink"] = INTEGER(file_stat.symlink);
  r["inode"] = BIGINT(file_stat.inode);
  r["uid"] = BIGINT(file_stat.uid);
  r["gid"] = BIGINT(file_stat.gid);
  r["mode"] = SQL_TEXT(file_stat.mode);
  r["device"] = BIGINT(file_stat.device);
  r["size"] = BIGINT(file_stat.size);
  r["block_size"] = INTEGER(file_stat.block_size);
  r["hard_links"] = INTEGER(file_stat.hard_links);
  r["atime"] = BIGINT(file_stat.atime);
  r["mtime"] = BIGINT(file_stat.mtime);
  r["ctime"] = BIGINT(file_stat.ctime);
  r["btime"] = BIGINT(file_stat.btime);
  r["type"] = SQL_TEXT(file_stat.type);
  r["attributes"] = SQL_TEXT(file_stat.attributes);
  r["file_id"] = SQL_TEXT(file_stat.file_id);
  r["volume_serial"] = SQL_TEXT(file_stat.volume_serial);
  r["product_version"] = SQL_TEXT(file_stat.product_version);
  r["file_version"] = SQL_TEXT(file_stat.file_version);

#endif

  results.push_back(r);
}

void transverseFileSystem(QueryData& results,
                          const std::string& start_path,
                          const int& limit) {
  std::vector<std::string> paths;

  fs::recursive_directory_iterator start(start_path), end;
  while (start != end) {

    // Skip firmlinks on macos
    if (start->path().string() == "/System/Volumes/Data" ||
        start->path().string() == "/Volumes/Macintosh HD") {
      start.no_push();
    }
    paths.push_back(start->path().string());
    if (start.level() == limit) {
      start.no_push();
    }
    boost::system::error_code ec;
    start.increment(ec);
    if (ec) {
      LOG(INFO) << ec.message() << ": " << start->path();
      start.no_push();
    }
  }
  
  // Iterate through each of the resolved/supplied paths.
  for (const auto& path_string : paths) {
    fs::path path = path_string;
    genFileInfo(path, path.parent_path(), "", start_path, limit, results);
  }

}

QueryData genFileImpl(QueryContext& context, Logger& logger) {
  QueryData results;
  auto start_path_array = context.constraints["start_path"].getAll(EQUALS);
  auto limit_array = context.constraints["path_limit"].getAll(EQUALS);

  if (start_path_array.empty() || limit_array.size() > 1) {
    LOG(INFO) << "Got empty path and/or more than one limit";
  }

  for (const auto& start_path : start_path_array) {
    boost::filesystem::path check_path = start_path;
    auto status = pathExists(check_path);
    if (!status.ok()) {
      LOG(INFO) << "Path does not exist";
      return results;
    }
    if (limit_array.empty()) {
      transverseFileSystem(results, start_path, 1);
    } else {
      auto limit_iter = limit_array.begin();
      int limit = std::stoi(*limit_iter);
      transverseFileSystem(results, start_path, limit);
    }
  }
  return results;
}

QueryData genFile(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "file", genFileImpl);
  } else {
    GLOGLogger logger;
    return genFileImpl(context, logger);
  }
}
} // namespace tables
} // namespace osquery
