/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>

#include <fcntl.h>
#include <glob.h>
#include <pwd.h>
#include <sys/stat.h>

#include <boost/algorithm/string.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

namespace pt = boost::property_tree;
namespace fs = boost::filesystem;

namespace osquery {

Status writeTextFile(const fs::path& path,
                     const std::string& content,
                     int permissions,
                     bool force_permissions) {
  // Open the file with the request permissions.
  int output_fd =
      open(path.c_str(), O_CREAT | O_APPEND | O_WRONLY, permissions);
  if (output_fd <= 0) {
    return Status(1, "Could not create file: " + path.string());
  }

  // If the file existed with different permissions before our open
  // they must be restricted.
  if (chmod(path.c_str(), permissions) != 0) {
    // Could not change the file to the requested permissions.
    return Status(1, "Failed to change permissions for file: " + path.string());
  }

  auto bytes = write(output_fd, content.c_str(), content.size());
  if (bytes != content.size()) {
    close(output_fd);
    return Status(1, "Failed to write contents to file: " + path.string());
  }

  close(output_fd);
  return Status(0, "OK");
}

Status readFile(const fs::path& path, std::string& content) {
  auto path_exists = pathExists(path);
  if (!path_exists.ok()) {
    return path_exists;
  }

  std::stringstream buffer;
  fs::ifstream file_h(path);
  if (file_h.is_open()) {
    buffer << file_h.rdbuf();
    if (file_h.bad()) {
      return Status(1, "Error reading file: " + path.string());
    }
    content.assign(std::move(buffer.str()));
  } else {
    return Status(1, "Could not open file: " + path.string());
  }

  return Status(0, "OK");
}

Status isWritable(const fs::path& path) {
  auto path_exists = pathExists(path);
  if (!path_exists.ok()) {
    return path_exists;
  }

  if (access(path.c_str(), W_OK) == 0) {
    return Status(0, "OK");
  }
  return Status(1, "Path is not writable: " + path.string());
}

Status isReadable(const fs::path& path) {
  auto path_exists = pathExists(path);
  if (!path_exists.ok()) {
    return path_exists;
  }

  if (access(path.c_str(), R_OK) == 0) {
    return Status(0, "OK");
  }
  return Status(1, "Path is not readable: " + path.string());
}

Status pathExists(const fs::path& path) {
  if (path.empty()) {
    return Status(1, "-1");
  }

  // A tri-state determination of presence
  try {
    if (!fs::exists(path)) {
      return Status(1, "0");
    }
  } catch (const fs::filesystem_error& e) {
    return Status(1, e.what());
  }
  return Status(0, "1");
}

Status remove(const fs::path& path) {
  auto status_code = std::remove(path.string().c_str());
  return Status(status_code, "N/A");
}

static void genGlobs(std::string path,
                     std::vector<std::string>& results,
                     GlobLimits limits) {
  // Replace SQL-wildcard '%' with globbing wildcard '*'.
  if (path.find("%") != std::string::npos) {
    boost::replace_all(path, "%", "*");
  } 

  // Relative paths are a bad idea, but we try to accommodate.
  if ((path.size() == 0 || path[0] != '/') && path[0] != '~') {
    path = (fs::initial_path() / path).string();
  }

  // Generate a glob set and recurse for double star.
  while (true) {
    glob_t data;
    glob(path.c_str(), GLOB_TILDE | GLOB_MARK | GLOB_BRACE, nullptr, &data);
    size_t count = data.gl_pathc;
    for (size_t index = 0; index < count; index++) {
      results.push_back(data.gl_pathv[index]);
    }
    globfree(&data);
    // The end state is a non-recursive ending or empty set of matches.
    size_t wild = path.rfind("**");
    // Allow a trailing slash after the double wild indicator.
    if (count == 0 || wild > path.size() || wild < path.size() - 3) {
      break;
    }
    path += "/**";
  }

  // Prune results based on settings/requested glob limitations.
  auto end = std::remove_if(
      results.begin(), results.end(), [limits](const std::string& found) {
        return !((found[found.length() - 1] == '/' && limits & GLOB_FOLDERS) ||
                 (found[found.length() - 1] != '/' && limits & GLOB_FILES));
      });
  results.erase(end, results.end());
}

Status resolveFilePattern(const fs::path& fs_path,
                          std::vector<std::string>& results) {
  return resolveFilePattern(fs_path, results, GLOB_ALL);
}

Status resolveFilePattern(const fs::path& fs_path,
                          std::vector<std::string>& results,
                          GlobLimits setting) {
  genGlobs(fs_path.string(), results, setting);
  return Status(0, "OK");
}

inline Status listInAbsoluteDirectory(const fs::path& path,
                                      std::vector<std::string>& results,
                                      GlobLimits limits) {
  try {
    if (path.filename() == "*" && !fs::exists(path.parent_path())) {
      return Status(1, "Directory not found: " + path.parent_path().string());
    }

    if (path.filename() == "*" && !fs::is_directory(path.parent_path())) {
      return Status(1, "Path not a directory: " + path.parent_path().string());
    }
  } catch (const fs::filesystem_error& e) {
    return Status(1, e.what());
  }
  genGlobs(path.string(), results, limits);
  return Status(0, "OK");
}

Status listFilesInDirectory(const fs::path& path,
                            std::vector<std::string>& results,
                            bool ignore_error) {
  return listInAbsoluteDirectory((path / "*"), results, GLOB_FILES);
}

Status listDirectoriesInDirectory(const fs::path& path,
                                  std::vector<std::string>& results,
                                  bool ignore_error) {
  return listInAbsoluteDirectory((path / "*"), results, GLOB_FOLDERS);
}

Status getDirectory(const fs::path& path, fs::path& dirpath) {
  if (!isDirectory(path).ok()) {
    dirpath = fs::path(path).parent_path().string();
    return Status(0, "OK");
  }
  dirpath = path;
  return Status(1, "Path is a directory: " + path.string());
}

Status isDirectory(const fs::path& path) {
  try {
    if (fs::is_directory(path)) {
      return Status(0, "OK");
    }
    return Status(1, "Path is not a directory: " + path.string());
  } catch (const fs::filesystem_error& e) {
    return Status(1, e.what());
  }
}

std::set<fs::path> getHomeDirectories() {
  std::set<fs::path> results;

  auto users = SQL::selectAllFrom("users");
  for (const auto& user : users) {
    if (user.at("directory").size() > 0) {
      results.insert(user.at("directory"));
    }
  }

  return results;
}

bool safePermissions(const std::string& dir,
                     const std::string& path,
                     bool executable) {
  struct stat file_stat, link_stat, dir_stat;
  if (lstat(path.c_str(), &link_stat) < 0 || stat(path.c_str(), &file_stat) ||
      stat(dir.c_str(), &dir_stat)) {
    // Path was not real, had too may links, or could not be accessed.
    return false;
  }

  if (dir_stat.st_mode & (1 << 9)) {
    // Do not load modules from /tmp-like directories.
    return false;
  } else if (S_ISDIR(file_stat.st_mode)) {
    // Only load file-like nodes (not directories).
    return false;
  } else if (file_stat.st_uid == getuid() || file_stat.st_uid == 0) {
    // Otherwise, require matching or root file ownership.
    if (executable && !(file_stat.st_mode & S_IXUSR)) {
      // Require executable, implies by the owner.
      return false;
    }
    return true;
  }
  // Do not load modules not owned by the user.
  return false;
}

const std::string& osqueryHomeDirectory() {
  static std::string homedir;
  if (homedir.size() == 0) {
    // Try to get the caller's home directory using HOME and getpwuid.
    auto user = getpwuid(getuid());
    if (getenv("HOME") != nullptr && isWritable(getenv("HOME")).ok()) {
      homedir = std::string(getenv("HOME")) + "/.osquery";
    } else if (user != nullptr && user->pw_dir != nullptr) {
      homedir = std::string(user->pw_dir) + "/.osquery";
    } else {
      // Failover to a temporary directory (used for the shell).
      homedir = "/tmp/osquery";
    }
  }
  return homedir;
}

std::string lsperms(int mode) {
  static const char rwx[] = {'0', '1', '2', '3', '4', '5', '6', '7'};
  std::string bits;

  bits += rwx[(mode >> 9) & 7];
  bits += rwx[(mode >> 6) & 7];
  bits += rwx[(mode >> 3) & 7];
  bits += rwx[(mode >> 0) & 7];
  return bits;
}

Status parseJSON(const fs::path& path, pt::ptree& tree) {
  std::string json_data;
  if (!readFile(path, json_data).ok()) {
    return Status(1, "Could not read JSON from file");
  }

  return parseJSONContent(json_data, tree);
}

Status parseJSONContent(const std::string& content, pt::ptree& tree) {
  // Read the extensions data into a JSON blob, then property tree.
  try {
    std::stringstream json_stream;
    json_stream << content;
    pt::read_json(json_stream, tree);
  } catch (const pt::json_parser::json_parser_error& e) {
    return Status(1, "Could not parse JSON from file");
  }
  return Status(0, "OK");
}
}
