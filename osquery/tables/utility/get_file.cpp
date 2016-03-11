/*
 *  Copyright (c) 2014-present, Facebook, Inc.
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

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__linux__)
const char token_charset[] =
  "0123456789"
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "abcdefghijklmnopqrstuvwxyz";
#else
  const char token_charset[] =
  "0123456789"
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
#endif 

std::string genFileToken(const size_t token_len) {
  auto randchar = []() -> char {
    const size_t max_index = (sizeof(token_charset) - 1);
    return token_charset[rand() % max_index];
  };

  std::string token(token_len,0);
  std::generate_n (token.begin(), token_len, randchar);

  return token;
}

void genGetFileContent(const fs::path& path,
                 const fs::path& parent,
                 const std::string& pattern,
                 QueryData& results) {
  // Must provide the path, filename, directory separate from boost path->string
  // helpers to match any explicit (query-parsed) predicate constraints.
  struct stat file_stat, link_stat;
  if (lstat(path.string().c_str(), &link_stat) < 0 ||
      stat(path.string().c_str(), &file_stat)) {
    // Path was not real, had too may links, or could not be accessed.
    return;
  }

  // Type booleans
  boost::system::error_code ec;
  auto status = fs::status(path, ec);
  if (kTypeNames.at(status.type()) != "regular") {
    return;
  }

  Row r;
  if (kTypeNames.count(status.type())) {
    r["type"] = kTypeNames.at(status.type());
  } else {
    r["type"] = "unknown";
  }

  r["path"] = path.string();
  r["filename"] = path.filename().string();
  r["directory"] = parent.string();
  r["size"] = BIGINT(file_stat.st_size);
  r["offset"] = BIGINT(0);

  std::string getfile_path = Flag::getValue("getfile_path").c_str();
  auto token = genFileToken(12);
  auto token_path = getfile_path + "/" + token;
  r["token"] = TEXT(token_path);

  fs::copy_file(path.string().c_str(), token_path, ec);
  results.push_back(r);
}

QueryData genGetFile(QueryContext& context) {
  QueryData results;

  // Resolve file paths for EQUALS and LIKE operations.
  auto paths = context.constraints["path"].getAll(EQUALS);
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

  // Iterate through each of the resolved/supplied paths.
  for (const auto& path_string : paths) {
    fs::path path = path_string;
    genGetFileContent(path, path.parent_path(), "", results);
  }

  // Resolve directories for EQUALS and LIKE operations.
  auto directories = context.constraints["directory"].getAll(EQUALS);
  context.expandConstraints(
      "directory",
      LIKE,
      directories,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_FOLDERS | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));

  // Now loop through constraints using the directory column constraint.
  for (const auto& directory_string : directories) {
    if (!isReadable(directory_string) || !isDirectory(directory_string)) {
      continue;
    }

    try {
      // Iterate over the directory and generate info for each regular file.
      fs::directory_iterator begin(directory_string), end;
      for (; begin != end; ++begin) {
        genGetFileContent(begin->path(), directory_string, "", results);
      }
    } catch (const fs::filesystem_error& e) {
      continue;
    }
  }

  return results;
}
}
}