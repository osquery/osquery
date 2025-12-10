/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <codecvt>
#include <sstream>

#include <fcntl.h>
#include <sys/stat.h>

#ifndef WIN32
#include <glob.h>
#include <pwd.h>
#include <sys/time.h>
#endif

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#if WIN32
#include <osquery/utils/conversions/windows/strings.h>
#endif
#include <osquery/utils/json/json.h>
#include <osquery/utils/system/system.h>

namespace fs = boost::filesystem;
namespace errc = boost::system::errc;

namespace osquery {

FLAG(uint64, read_max, 50 * 1024 * 1024, "Maximum file read size");

/// See reference #1382 for reasons why someone would allow unsafe.
HIDDEN_FLAG(bool, allow_unsafe, false, "Allow unsafe executable permissions");

namespace {
const size_t kMaxRecursiveGlobs = 64;

constexpr std::size_t kBlockSize = 16384;

Status checkFileReadLimit(std::size_t file_size,
                          const fs::path& path,
                          bool shouldLog) {
  if (file_size > FLAGS_read_max) {
    auto error_message = "Cannot read " + path.string() +
                         " size exceeds limit: " + std::to_string(file_size) +
                         " > " + std::to_string(FLAGS_read_max);
    if (shouldLog) {
      LOG(WARNING) << error_message;
    }
    return Status::failure(error_message);
  }

  return Status::success();
}
} // namespace

Status writeTextFile(const fs::path& path,
                     const std::string& content,
                     int permissions,
                     int mode) {
  // Open the file with the request permissions.
  PlatformFile output_fd(path, mode, permissions);
  if (!output_fd.isValid()) {
    return Status(1, "Could not create file: " + path.string());
  }

  // If the file existed with different permissions before our open
  // they must be restricted.
#if WIN32
  const std::string p = wstringToString(path.wstring());
#else
  const std::string p = path.string();
#endif
  if (!platformChmod(p, permissions)) {
    // Could not change the file to the requested permissions.
    return Status(1, "Failed to change permissions for file: " + path.string());
  }

  ssize_t bytes = output_fd.write(content.c_str(), content.size());
  if (static_cast<size_t>(bytes) != content.size()) {
    return Status(1, "Failed to write contents to file: " + path.string());
  }

  return Status::success();
}

void initializeFilesystemAPILocale() {
#if defined(WIN32)
  setlocale(LC_ALL, ".UTF-8");

  boost::filesystem::path::imbue(std::locale(
      std::locale(".UTF-8"), new std::codecvt_utf8_utf16<wchar_t>()));
#endif
}

Status readFile(const fs::path& path,
                std::function<void(std::string_view)> predicate,
                bool shouldLog) {
  PlatformFile file_handle(path, PF_OPEN_EXISTING | PF_READ | PF_NONBLOCK);

  if (!file_handle.isValid()) {
    return Status::failure("Cannot open file for reading: " +
                           file_handle.getFilePath().string());
  }

  const std::uint64_t file_size = file_handle.size();

  // Fail to read if the file is bigger than the configured limit.
  auto status = checkFileReadLimit(file_size, path, shouldLog);
  if (!status.ok()) {
    return status;
  }

  const bool isSpecialFile = file_handle.isSpecialFile();

  /* If the file is a regular file on disk and has no data,
     do not attempt to read */
  if (!isSpecialFile && file_size == 0) {
    return Status::success();
  }

  ssize_t res = 0;
  std::size_t total_bytes = 0;
  char buffer[kBlockSize];

  do {
    res = file_handle.read(buffer, kBlockSize);

    // EOF
    if (res == 0) {
      break;
    }

    if (res > 0) {
      total_bytes += res;
      status = checkFileReadLimit(total_bytes, path, shouldLog);

      if (!status.ok()) {
        return status;
      }

      predicate({buffer, static_cast<std::size_t>(res)});
    }
  } while (res > 0 || (!isSpecialFile && file_handle.hasPendingIo()));

  if (res < 0) {
    return Status::failure("Failed to read " + path.string());
  }

  return Status::success();
}

Status readFile(const fs::path& path, std::string& content, bool shouldLog) {
  PlatformFile file_handle(path, PF_OPEN_EXISTING | PF_READ | PF_NONBLOCK);

  if (!file_handle.isValid()) {
    return Status::failure("Cannot open file for reading: " +
                           file_handle.getFilePath().string());
  }

  const std::uint64_t file_size = file_handle.size();

  // Fail to read if the file is bigger than the configured limit
  auto status = checkFileReadLimit(file_size, path, shouldLog);

  if (!status.ok()) {
    return status;
  }

  const bool isSpecialFile = file_handle.isSpecialFile();

  /* If the file is a regular file on disk and has no data,
   do not attempt to read */
  if (!isSpecialFile && file_size == 0) {
    return Status::success();
  }

  /* We read in blocks only if we don't know the file size;
     otherwise use the file size for efficiency */
  std::size_t read_size = 0;
  if (file_size > 0) {
    read_size = file_size;
    content.resize(file_size);
  } else {
    read_size = kBlockSize;
    content.resize(kBlockSize);
  }

  std::size_t offset = 0;
  ssize_t res = 0;

  do {
    res = file_handle.read(&content[offset], read_size);

    // EOF
    if (res == 0) {
      break;
    }

    if (res > 0) {
      offset += res;
      auto status = checkFileReadLimit(offset, path, shouldLog);

      if (!status.ok()) {
        content.clear();
        return status;
      }

      if (file_size > 0) {
        read_size = file_size - offset;
      } else {
        content.resize(content.size() + kBlockSize);
      }
    }
  } while (read_size > 0 &&
           (res > 0 || (!isSpecialFile && file_handle.hasPendingIo())));

  if (res < 0) {
    content.clear();
    return Status::failure("Failed to read " + path.string());
  }

  content.resize(offset);

  return Status::success();
}

Status isWritable(const fs::path& path, bool effective) {
  auto path_exists = pathExists(path);
  if (!path_exists.ok()) {
    return path_exists;
  }

  if (effective) {
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_WRITE);
    return Status(fd.isValid() ? 0 : 1);
  } else if (platformAccess(path.string(), W_OK) == 0) {
    return Status::success();
  }

  return Status(1, "Path is not writable: " + path.string());
}

Status isReadable(const fs::path& path, bool effective) {
  auto path_exists = pathExists(path);
  if (!path_exists.ok()) {
    return path_exists;
  }

  if (effective) {
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_READ);
    return Status(fd.isValid() ? 0 : 1);
  } else if (platformAccess(path.string(), R_OK) == 0) {
    return Status::success();
  }

  return Status(1, "Path is not readable: " + path.string());
}

Status pathExists(const fs::path& path) {
  boost::system::error_code ec;
  if (path.empty()) {
    return Status(1, "-1");
  }

  // A tri-state determination of presence
  if (!fs::exists(path, ec) || ec.value() != errc::success) {
    return Status(1, ec.message());
  }
  return Status::success();
}

Status movePath(const fs::path& from, const fs::path& to) {
  boost::system::error_code ec;
  if (from.empty() || to.empty()) {
    return Status(1, "Cannot copy empty paths");
  }

  fs::rename(from, to, ec);
  if (ec.value() != errc::success) {
    return Status(1, ec.message());
  }
  return Status(0);
}

Status removePath(const fs::path& path) {
  boost::system::error_code ec;
  auto removed_files = fs::remove_all(path, ec);
  if (ec.value() != errc::success) {
    return Status(1, ec.message());
  }
  return Status(0, std::to_string(removed_files));
}

static bool isDirVisited(std::unordered_set<int>& dir_inos,
                         const std::string& path) {
  if (path.empty()) {
    return true;
  }

  struct stat d_stat;
  // On Windows systems (lstat not implemented) this immediately returns
  if (!platformLstat(path, d_stat).ok()) {
    return false;
  }

  auto [_, inserted] = dir_inos.emplace(d_stat.st_ino);
  return !inserted;
}

static void dfsTraverseDirectories(const std::string& current_path,
                                   std::unordered_set<int>& visited_dirs,
                                   std::vector<std::string>& results,
                                   size_t depth) {
  if (depth >= kMaxRecursiveGlobs) {
    return;
  }

  if (isDirVisited(visited_dirs, current_path)) {
    return;
  }

  boost::system::error_code ec;
  if (!fs::exists(current_path, ec) || !fs::is_directory(current_path, ec)) {
    return;
  }

  for (fs::directory_iterator entry(
           current_path, fs::directory_options::skip_permission_denied, ec),
       end;
       entry != end;
       entry.increment(ec)) {
    std::string entry_path = entry->path().string();
    bool is_dir = fs::is_directory(entry->status(ec));

    // Add trailing separator for directories to match platformGlob behavior
    // (which uses GLOB_MARK to add trailing slashes)
    if (is_dir && entry_path.back() != '/' && entry_path.back() != '\\') {
      entry_path += fs::path::preferred_separator;
    }

    results.push_back(entry_path);

    if (is_dir) {
      dfsTraverseDirectories(entry_path, visited_dirs, results, depth + 1);
    }
  }
}

static void genGlobs(std::string path,
                     std::vector<std::string>& results,
                     GlobLimits limits) {
  // Use our helped escape/replace for wildcards.
  replaceGlobWildcards(path, limits);

  // inodes of traversed directories to avoid loops from symlinks
  std::unordered_set<int> dir_inos;

  bool should_expand =
      (path.size() >= 2 && path.substr(path.size() - 2) == "**");
  if (should_expand) {
    // Replace ** with * since platformGlob doesn't understand ** as recursive
    // We'll handle recursion manually via dfsTraverseDirectories
    std::string glob_path = path.substr(0, path.size() - 1);
    auto initial_results = platformGlob(glob_path);

    for (const auto& base_dir : initial_results) {
      boost::system::error_code ec;
      results.push_back(base_dir);
      if (fs::is_directory(base_dir, ec)) {
        dfsTraverseDirectories(base_dir, dir_inos, results, 0);
      }
    }
  } else {
    auto glob_results = platformGlob(path);
    for (auto& result : glob_results) {
      results.push_back(result);
    }
  }

  // Prune results based on settings/requested glob limitations.
  auto end = std::remove_if(
      results.begin(), results.end(), [limits](const std::string& found) {
        return !(((found[found.length() - 1] == '/' ||
                   found[found.length() - 1] == '\\') &&
                  limits & GLOB_FOLDERS) ||
                 ((found[found.length() - 1] != '/' &&
                   found[found.length() - 1] != '\\') &&
                  limits & GLOB_FILES));
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
  return Status::success();
}

inline void replaceGlobWildcards(std::string& pattern, GlobLimits limits) {
  // Replace SQL-wildcard '%' with globbing wildcard '*'.
  if (pattern.find('%') != std::string::npos) {
    boost::replace_all(pattern, "%", "*");
  }

  // Relative paths are a bad idea, but we try to accommodate.
  if ((pattern.size() == 0 || ((pattern[0] != '/' && pattern[0] != '\\') &&
                               (pattern.size() > 3 && pattern[1] != ':' &&
                                pattern[2] != '\\' && pattern[2] != '/'))) &&
      pattern[0] != '~') {
    try {
      boost::system::error_code ec;
      pattern = (fs::current_path(ec) / pattern).make_preferred().string();
    } catch (const fs::filesystem_error& /* e */) {
      // There is a bug in versions of current_path that still throw.
    }
  }

  auto base =
      fs::path(pattern.substr(0, pattern.find('*'))).make_preferred().string();

  if (base.size() > 0) {
    boost::system::error_code ec;
    auto canonicalized = ((limits & GLOB_NO_CANON) == 0)
                             ? fs::canonical(base, ec).make_preferred().string()
                             : base;

    if (canonicalized.size() > 0 && canonicalized != base) {
      if (isDirectory(canonicalized)) {
        // Canonicalized directory paths will not include a trailing '/'.
        // However, if the wildcards are applied to files within a directory
        // then the missing '/' changes the wildcard meaning.
        canonicalized += '/';
      }
      // We are unable to canonicalize the meaning of post-wildcard limiters.
      pattern = fs::path(canonicalized + pattern.substr(base.size()))
                    .make_preferred()
                    .string();
    }
  }
}

inline Status listInAbsoluteDirectory(const fs::path& path,
                                      std::vector<std::string>& results,
                                      GlobLimits limits) {
  if (path.filename() == "*" && !pathExists(path.parent_path())) {
    return Status(1, "Directory not found: " + path.parent_path().string());
  }

  if (path.filename() == "*" && !isDirectory(path.parent_path())) {
    return Status(1, "Path not a directory: " + path.parent_path().string());
  }

  genGlobs(path.string(), results, limits);
  return Status::success();
}

Status listFilesInDirectory(const fs::path& path,
                            std::vector<std::string>& results,
                            bool recursive) {
  return listInAbsoluteDirectory(
      (path / ((recursive) ? "**" : "*")), results, GLOB_FILES);
}

Status listDirectoriesInDirectory(const fs::path& path,
                                  std::vector<std::string>& results,
                                  bool recursive) {
  // We don't really need the error, but by passing it into
  // recursive_directory_iterator we invoke the non-throw version.
  boost::system::error_code ignored_ec;
  if (path.empty() || !pathExists(path) ||
      !fs::is_directory(path, ignored_ec)) {
    return Status(1, "Target directory is invalid");
  }

  auto status = listInAbsoluteDirectory(
      (path / ((recursive) ? "**" : "*")), results, GLOB_FOLDERS);

  if (!status.ok()) {
    return status;
  }

  // Remove trailing separators from directory paths
  for (auto& dir_path : results) {
    if (!dir_path.empty() &&
        (dir_path.back() == '/' || dir_path.back() == '\\')) {
      dir_path.pop_back();
    }
  }

  return status;
}

Status isDirectory(const fs::path& path) {
  boost::system::error_code ec;
  if (fs::is_directory(path, ec)) {
    return Status::success();
  }

  // The success error code is returned for as a failure (undefined error)
  // We need to flip that into an error, a success would have falling
  // through in the above conditional.
  if (ec.value() == errc::success) {
    return Status(1, "Path is not a directory: " + path.string());
  }
  return Status(ec.value(), ec.message());
}

Status createDirectory(const boost::filesystem::path& dir_path,
                       bool const recursive,
                       bool const ignore_existence) {
  auto err = boost::system::error_code{};
  bool is_created = false;
  if (recursive) {
    is_created = boost::filesystem::create_directories(dir_path, err);
  } else {
    is_created = boost::filesystem::create_directory(dir_path, err);
  }
  if (is_created) {
    return Status::success();
  }
  if (ignore_existence && isDirectory(dir_path).ok()) {
    return Status::success();
  }
  auto msg = std::string{"Could not create directory \""};
  msg += dir_path.string();
  msg += '"';
  if (err) {
    msg += ": ";
    msg += err.message();
  }
  return Status::failure(msg);
}

std::set<fs::path> getHomeDirectories() {
  std::set<fs::path> results;

  auto users = SQL::selectAllFrom("users");
  for (const auto& user : users) {
    // First verify the user has a "directory" entry.
    auto dir_iter = user.find("directory");
    if (dir_iter != user.end() && user.at("directory").size() > 0) {
      results.insert(user.at("directory"));
    }
  }

  return results;
}

bool safePermissions(const fs::path& dir,
                     const fs::path& path,
                     bool executable) {
  if (!platformIsFileAccessible(path).ok()) {
    // Path was not real, had too may links, or could not be accessed.
    return false;
  }

  if (FLAGS_allow_unsafe) {
    return true;
  }

  Status result = platformIsTmpDir(dir);
  if (!result.ok() && result.getCode() < 0) {
    // An error has occurred in stat() on dir, most likely because the file
    // path does not exist
    return false;
  } else if (result.ok()) {
    // Do not load modules from /tmp-like directories.
    return false;
  }

  PlatformFile fd(path, PF_OPEN_EXISTING | PF_READ);
  if (!fd.isValid()) {
    return false;
  }

  result = isDirectory(path);
  if (!result.ok() && result.getCode() < 0) {
    // Something went wrong when determining the file's directoriness
    return false;
  } else if (result.ok()) {
    // Only load file-like nodes (not directories).
    return false;
  }

  if (fd.isOwnerRoot().ok() || fd.isOwnerCurrentUser().ok()) {
    result = fd.isExecutable();

    // Otherwise, require matching or root file ownership.
    if (executable && (result.getCode() > 0 || !fd.hasSafePermissions().ok())) {
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
    // Try to get the caller's home directory
    boost::system::error_code ec;
    auto userdir = getHomeDirectory();
    if (userdir.is_initialized() && isWritable(*userdir).ok()) {
      auto osquery_dir = (fs::path(*userdir) / ".osquery");
      if (isWritable(osquery_dir) ||
          boost::filesystem::create_directories(osquery_dir, ec)) {
        homedir = osquery_dir.make_preferred().string();
        return homedir;
      }
    }

    // Fail over to a temporary directory (used for the shell).
    auto temp =
        fs::temp_directory_path(ec) /
        (std::string("osquery-") + std::to_string((rand() % 10000) + 20000));
    boost::filesystem::create_directories(temp, ec);
    homedir = temp.make_preferred().string();
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
} // namespace osquery
