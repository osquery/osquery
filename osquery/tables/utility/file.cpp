/**
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under both the Apache 2.0 license (found in the
*  LICENSE file in the root directory of this source tree) and the GPLv2 (found
*  in the COPYING file in the root directory of this source tree).
*  You may select, at your option, one of the above-listed licenses.
*/


#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <Shlwapi.h>

#include <boost/filesystem.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include "osquery\filesystem\fileops.h"


namespace fs = boost::filesystem;

namespace osquery {

int getUidFromSid(PSID sid);
int getGidFromSid(PSID sid);
LONGLONG filetimeToUnixtime(const FILETIME& ft);
LONGLONG longIntToUnixtime(LARGE_INTEGER& ft);

namespace tables {

#if defined(WIN32)

const std::map<std::int32_t, std::string> kDriveLetters{
    {0, "A:\\\0"},  {1, "B:\\\0" },  {2, "C:\\\0" },  {3, "D:\\\0" },  {4, "E:\\\0" },  {5, "F:\\\0" },  {6, "G:\\\0" },
    {7, "H:\\\0" },  {8, "I:\\\0" },  {9, "J:\\\0" },  {10, "K:\\\0" }, {11, "L:\\\0" }, {12, "M:\\\0" }, {13, "N:\\\0" },
    {14, "O:\\\0" }, {15, "P:\\\0" }, {16, "Q:\\\0" }, {17, "R:\\\0" }, {18, "S:\\\0" }, {19, "T:\\\0" }, {20, "U:\\\0" },
    {21, "V:\\\0" }, {22, "W:\\\0" }, {23, "X:\\\0" }, {24, "Y:\\\0" }, {25, "Z:\\\0" },
};

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

void genFileInfo(const fs::path& path,
                 const fs::path& parent,
                 const std::string& pattern,
                 QueryData& results) {
// Must provide the path, filename, directory separate from boost path->string
// helpers to match any explicit (query-parsed) predicate constraints.

#if defined(WIN32)

  
  PSID sid_owner = nullptr;
  SID_NAME_USE name_use = SidTypeUnknown;
  PSECURITY_DESCRIPTOR security_descriptor = NULL;

#endif

  Row r;
  r["path"] = path.string();
  r["filename"] = path.filename().string();
  r["directory"] = parent.string();
  r["symlink"] = "0";

#if !defined(WIN32)

  struct stat file_stat;

  // On POSIX systems, first check the link state.
  struct stat link_stat;
  if (lstat(path.string().c_str(), &link_stat) < 0) {
    // Path was not real, had too may links, or could not be accessed.
    return;
  }
  if ((link_stat.st_mode & S_IFLNK) != 0) {
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

#else

  // Get the handle of the file object.
  auto file_handle = CreateFile(TEXT(path.string().c_str()),
                     GENERIC_READ,
                     FILE_SHARE_READ,
                     NULL,
                     OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL,
                     NULL);

  // Check GetLastError for CreateFile error code.
  if (file_handle == INVALID_HANDLE_VALUE) {
	CloseHandle(file_handle);
    return;
  }

  // Get the owner SID of the file.
  auto ret = GetSecurityInfo(file_handle,
                              SE_FILE_OBJECT,
                              OWNER_SECURITY_INFORMATION,
                              &sid_owner,
                              NULL,
                              NULL,
                              NULL,
                              &security_descriptor);

  // Check GetLastError for GetSecurityInfo error condition.
  if (ret != ERROR_SUCCESS) {
	CloseHandle(file_handle);
    return;
  }

  FILE_BASIC_INFO basic_info;
  BY_HANDLE_FILE_INFORMATION file_info;

  if (0 == GetFileInformationByHandle(file_handle, &file_info)) {
	CloseHandle(file_handle);
    return;
  }

  auto file_index = (static_cast<unsigned long long>(file_info.nFileIndexHigh) << 32) +
	  static_cast<unsigned long long>(file_info.nFileIndexLow);

  std::stringstream stream;
  stream << "0x" << std::setfill('0')
         << std::setw(sizeof(unsigned long long) * 2) << std::hex << file_index;
  std::string file_id(stream.str());

  // Windows has fileid's that are displayed in hex using: 
  // fsutil file queryfileid <filename>
  r["file_id"] = TEXT(file_id);

  // inode is the decimal equivalent of fileid
  r["inode"] = BIGINT(file_index);
  r["uid"] = INTEGER(getUidFromSid(sid_owner));
  r["gid"] = INTEGER(getGidFromSid(sid_owner));

  // Permission bits don't make sense for Windows. Use ntfs_acl_permissions
  // table
  r["mode"] = "-1";

  auto file_type = GetFileType(file_handle);

  // Try to assign a human readable file type
  switch (file_type) {

	  {
  case FILE_TYPE_CHAR:

	  r["type"] = "Character";
	  break;

  case FILE_TYPE_DISK:

	  if (file_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
		  r["type"] = "Directory";

	  }
	  else if (file_info.dwFileAttributes & FILE_ATTRIBUTE_NORMAL) {
		  r["type"] = "Regular";
	  }

	  else if (file_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		  r["type"] = "Symbolic";
		  r["symlink"] = "1";

	  }
	  else {
		  // This is the type returned from GetFileType -> FILE_TYPE_DISK
		  r["type"] = "Disk";
	  }
	  break;

  case FILE_TYPE_PIPE:

	  // If GetNamedPipeInfo fails we assume it's a socket
	  (GetNamedPipeInfo(file_handle, 0, 0, 0, 0)) ? r["type"] = "Pipe"
		  : r["type"] = "Socket";
	  break;

  default:
	  r["type"] = "Unknown";

	  }
  }

  r["attributes"] = getFileAttribStr(file_info.dwFileAttributes);

  std::stringstream volume_serial;
  volume_serial << std::hex << std::setfill('0') << std::setw(4)
               << HIWORD(file_info.dwVolumeSerialNumber) << "-" << std::setw(4)
               << LOWORD(file_info.dwVolumeSerialNumber);

  r["device"] = BIGINT(file_info.dwVolumeSerialNumber);
  r["volume_serial"] = TEXT(volume_serial.str());

  LARGE_INTEGER li = {0};
  (GetFileSizeEx(file_handle, &li) == 0) ? r["size"] = BIGINT(-1)
                                   : r["size"] = BIGINT(li.QuadPart);

  const char* drive_letter = nullptr;
  auto drive_letter_index = PathGetDriveNumber(path.string().c_str());

  if (drive_letter_index != -1 && kDriveLetters.count(drive_letter_index)) {
   
      drive_letter = kDriveLetters.at(drive_letter_index).c_str();
      

      unsigned long sect_per_cluster;
      unsigned long bytes_per_sect;
      unsigned long free_clusters;
      unsigned long total_clusters;

      if (GetDiskFreeSpace(drive_letter,
                           &sect_per_cluster,
                           &bytes_per_sect,
                           &free_clusters,
                           &total_clusters) != 0) {
        r["block_size"] = INTEGER(bytes_per_sect);
      }
    

  } else {
    r["block_size"] = INTEGER(-1);
  }

  r["hard_links"] = INTEGER(file_info.nNumberOfLinks);
  r["atime"] = BIGINT(filetimeToUnixtime(file_info.ftLastAccessTime));
  r["mtime"] = BIGINT(filetimeToUnixtime(file_info.ftLastWriteTime));
  r["btime"] = BIGINT(filetimeToUnixtime(file_info.ftCreationTime));

  // Change time is not available in GetFileInformationByHandle
 ret = GetFileInformationByHandleEx(
      file_handle, FileBasicInfo, &basic_info, sizeof(basic_info));

  (!ret) ? r["ctime"] = BIGINT(-1)
              : r["ctime"] = BIGINT(longIntToUnixtime(basic_info.ChangeTime));

  CloseHandle(file_handle);

#endif

  results.push_back(r);
}

QueryData genFile(QueryContext& context) {
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
    genFileInfo(path, path.parent_path(), "", results);
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
        genFileInfo(begin->path(), directory_string, "", results);
      }
    } catch (const fs::filesystem_error& /* e */) {
      continue;
    }
  }

  return results;
}
}
}
