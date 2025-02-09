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
#else
#include <shobjidl.h>

#include <ShlGuid.h>
#include <shellapi.h>

#include <osquery/utils/conversions/windows/strings.h>
#endif

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/fileops.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/scope_guard.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace fs = boost::filesystem;

namespace osquery {

namespace tables {

namespace {
#ifdef WIN32

/* These are the number of bytes to read from the ShellLinkHeader structure
   at the start of a ShellLink file for the "HeaderSize" field */
constexpr std::uint32_t kShellLinkHeaderSizeFieldSize = 4;

// This is the expected value of the "HeaderSize" field
constexpr std::uint32_t kShellLinkHeaderSizeExpectedValue = 0x4C;

struct LnkData {
  std::string target_path;
  std::string target_type;
  std::string target_location;
  std::string start_in;
  std::string run;
  std::string comment;
};

std::string showCmdToString(int show_cmd) {
  switch (show_cmd) {
  case SW_SHOWNORMAL: {
    return "Normal window";
  }
  case SW_SHOWMAXIMIZED: {
    return "Maximized";
  }
  case SW_SHOWMINIMIZED: {
    return "Minimized";
  }
  default: {
    return "Unknown";
  }
  }
}

boost::optional<LnkData> parseLnkData(const fs::path& link) {
  IShellLink* shell_link;
  auto hres = CoCreateInstance(CLSID_ShellLink,
                               nullptr,
                               CLSCTX_INPROC_SERVER,
                               IID_IShellLink,
                               reinterpret_cast<LPVOID*>(&shell_link));
  if (FAILED(hres)) {
    TLOG << "Failed to create an instance of a shell link, error: "
         << shell_link;
    return boost::none;
  }

  auto shell_link_release =
      scope_guard::create([shell_link]() { shell_link->Release(); });

  IPersistFile* file;
  hres = shell_link->QueryInterface(IID_IPersistFile,
                                    reinterpret_cast<LPVOID*>(&file));

  if (FAILED(hres)) {
    TLOG << "Failed to create an instance of a shell link, error: "
         << shell_link;
    return boost::none;
  }

  auto file_link_release = scope_guard::create([file]() { file->Release(); });

  hres = file->Load(link.c_str(), STGM_READ);

  if (FAILED(hres)) {
    // Not a shell link
    return boost::none;
  }

  /* Empty files are still able to be loaded via the ShellLink COM interface,
     but they are not ShellLink files, so verify that the file
     contains a header of a certain size */
  std::string header_size_field_bytes;
  auto status =
      readFile(link, header_size_field_bytes, kShellLinkHeaderSizeFieldSize);

  if (!status.ok() ||
      header_size_field_bytes.size() != kShellLinkHeaderSizeFieldSize) {
    return boost::none;
  }

  std::uint32_t header_size_field_value;
  std::memcpy(&header_size_field_value,
              header_size_field_bytes.data(),
              kShellLinkHeaderSizeFieldSize);

  if (header_size_field_value != kShellLinkHeaderSizeExpectedValue) {
    return boost::none;
  }

  constexpr auto max_chars = INFOTIPSIZE > MAX_PATH ? INFOTIPSIZE : MAX_PATH;
  WCHAR buffer[max_chars + 1]{};

  WIN32_FIND_DATA target_data{};
  hres = shell_link->GetPath(&buffer[0], max_chars, &target_data, 0);

  if (FAILED(hres)) {
    return boost::none;
  }

  SHFILEINFO file_info{};
  auto res = SHGetFileInfoW(buffer,
                            target_data.dwFileAttributes,
                            &file_info,
                            sizeof(file_info),
                            SHGFI_TYPENAME | SHGFI_USEFILEATTRIBUTES);

  if (res == 0) {
    return boost::none;
  }

  LnkData link_data;

  link_data.target_path = wstringToString(buffer);

  auto type_name_length =
      wcsnlen(file_info.szTypeName, ARRAYSIZE(file_info.szTypeName));
  link_data.target_type =
      wstringToString(std::wstring(file_info.szTypeName, type_name_length));

  fs::path target_path = link_data.target_path;
  link_data.target_location = target_path.parent_path().filename().string();

  std::memset(buffer, 0, sizeof(buffer));
  hres = shell_link->GetWorkingDirectory(buffer, max_chars);

  if (FAILED(hres)) {
    return boost::none;
  }

  link_data.start_in = wstringToString(buffer);

  std::memset(buffer, 0, sizeof(buffer));
  hres = shell_link->GetDescription(buffer, max_chars);

  if (FAILED(hres)) {
    return boost::none;
  }

  link_data.comment = wstringToString(buffer);

  int show_cmd = 0;
  hres = shell_link->GetShowCmd(&show_cmd);

  if (FAILED(hres)) {
    return boost::none;
  }

  link_data.run = showCmdToString(show_cmd);

  return link_data;
}
#else
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

std::set<std::string> getPathsFromConstraints(const QueryContext& context) {
  auto constraint_it = context.constraints.find("path");

  if (constraint_it == context.constraints.end()) {
    return {};
  }

  auto paths = constraint_it->second.getAll(EQUALS);
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

  return paths;
}

std::set<std::string> getDirsFromConstraints(const QueryContext& context) {
  auto constraint_it = context.constraints.find("directory");

  if (constraint_it == context.constraints.end()) {
    return {};
  }

  auto directories = constraint_it->second.getAll(EQUALS);
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

  return directories;
}

} // namespace

#ifdef WIN32
void genFileInfoWindows(const fs::path& path,
                        const fs::path& parent,
                        const std::string& pattern,
                        bool get_shortcut_data,
                        QueryData& results) {
  // Must provide the path, filename, directory separate from boost path->string
  // helpers to match any explicit (query-parsed) predicate constraints.
  Row r;
  r["path"] = path.string();
  r["filename"] = path.filename().string();
  r["directory"] = parent.string();
  r["symlink"] = "0";

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
  r["original_filename"] = SQL_TEXT(file_stat.original_filename);

  if (get_shortcut_data) {
    auto opt_link_data = parseLnkData(path);

    if (opt_link_data.has_value()) {
      const auto& link_data = *opt_link_data;
      r["shortcut_target_path"] = link_data.target_path;
      r["shortcut_target_type"] = link_data.target_type;
      r["shortcut_target_location"] = link_data.target_location;
      r["shortcut_start_in"] = link_data.start_in;
      r["shortcut_run"] = link_data.run;
      r["shortcut_comment"] = link_data.comment;
    }
  }

  results.push_back(r);
}

QueryData genFileWindows(QueryContext& context, Logger& logger) {
  QueryData results;

  // Resolve file paths for EQUALS and LIKE operations.
  auto paths = getPathsFromConstraints(context);

  // Only get shortcut data if actually requested
  bool get_shortcut_data = context.isAnyColumnUsed({"shortcut_target_path",
                                                    "shortcut_target_type",
                                                    "shortcut_target_location",
                                                    "shortcut_start_in",
                                                    "shortcut_run",
                                                    "shortcut_comment"});

  // Iterate through each of the resolved/supplied paths.
  for (const auto& path_string : paths) {
    fs::path path = path_string;
    genFileInfoWindows(
        path, path.parent_path(), "", get_shortcut_data, results);
  }

  // Resolve directories for EQUALS and LIKE operations.
  auto directories = getDirsFromConstraints(context);

  // Now loop through constraints using the directory column constraint.
  for (const auto& directory_string : directories) {
    if (!isReadable(directory_string) || !isDirectory(directory_string)) {
      continue;
    }

    try {
      // Iterate over the directory and generate info for each regular file.
      fs::directory_iterator begin(directory_string), end;
      for (; begin != end; ++begin) {
        genFileInfoWindows(begin->path(), directory_string, "", false, results);
      }
    } catch (const fs::filesystem_error& /* e */) {
      continue;
    }
  }

  return results;
}

#else

void genFileInfoPosix(const fs::path& path,
                      const fs::path& parent,
                      const std::string& pattern,
                      QueryData& results) {
  // Must provide the path, filename, directory separate from boost path->string
  // helpers to match any explicit (query-parsed) predicate constraints.
  Row r;
  r["path"] = path.string();
  r["filename"] = path.filename().string();
  r["directory"] = parent.string();
  r["symlink"] = "0";

  struct stat file_stat;

  // On POSIX systems, first check the link state.
  struct stat link_stat;
  if (lstat(path.string().c_str(), &link_stat) < 0) {
    // Path was not real, had too may links, or could not be accessed.
    return;
  }
  if (S_ISLNK(link_stat.st_mode)) {
    r["symlink"] = "1";
    fs::path symlink_target = fs::read_symlink(path);
    r["symlink_target_path"] = symlink_target.string();
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

  results.push_back(r);
}

QueryData genFilePosix(QueryContext& context, Logger& logger) {
  QueryData results;

  // Resolve file paths for EQUALS and LIKE operations.
  auto paths = getPathsFromConstraints(context);

  // Iterate through each of the resolved/supplied paths.
  for (const auto& path_string : paths) {
    fs::path path = path_string;
    genFileInfoPosix(path, path.parent_path(), "", results);
  }

  // Resolve directories for EQUALS and LIKE operations.
  auto directories = getDirsFromConstraints(context);

  // Now loop through constraints using the directory column constraint.
  for (const auto& directory_string : directories) {
    if (!isReadable(directory_string) || !isDirectory(directory_string)) {
      continue;
    }

    try {
      // Iterate over the directory and generate info for each regular file.
      fs::directory_iterator begin(directory_string), end;
      for (; begin != end; ++begin) {
        genFileInfoPosix(begin->path(), directory_string, "", results);
      }
    } catch (const fs::filesystem_error& /* e */) {
      continue;
    }
  }

  return results;
}
#endif

QueryData genFileImpl(QueryContext& context, Logger& logger) {
#ifdef WIN32
  return genFileWindows(context, logger);
#else
  return genFilePosix(context, logger);
#endif
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
