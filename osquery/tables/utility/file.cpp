/**
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under both the Apache 2.0 license (found in the
*  LICENSE file in the root directory of this source tree) and the GPLv2 (found
*  in the COPYING file in the root directory of this source tree).
*  You may select, at your option, one of the above-listed licenses.
*/

#include <sys/stat.h>
#include <boost/filesystem.hpp>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include "Shlwapi.h"
#include "osquery\tables\utility\file_windows_ops.h"

namespace fs = boost::filesystem;

namespace osquery {

	int getUidFromSid(PSID sid);
	int getGidFromSid(PSID sid);
	time_t FileTimeToUnixTime(FILETIME & ft);
	time_t LongIntToUnixTime(LARGE_INTEGER & ft);


	namespace tables {

#if defined(WIN32)

		// File types referenced in  GetFileType docs plus some additions
		const std::map<std::int32_t, std::string> kTypeNames{
			{ FILE_TYPE_CHAR, "character" },	// The specified file is a character file, typically an LPT device or a console.
			{ FILE_TYPE_DISK, "disk" },			// The specified file is a disk file.
			{ FILE_TYPE_PIPE, "socket" },		// The specified file is a socket, a named pipe, or an anonymous pipe.
			{ FILE_TYPE_REMOTE, "remote" },		// Unused according to GetFileType docs
			{ FILE_TYPE_UNKNOWN, "unknown" },	// Either the type of the specified file is unknown, or the function failed.
		};

		const std::map<std::int32_t, char> kDriveLetters{
			{ 0, 'A' },
			{ 1, 'B' },
			{ 2, 'C' },
			{ 3, 'D' },
			{ 4, 'E' },
			{ 5, 'F' },
			{ 6, 'G' },
			{ 7, 'H' },
			{ 8, 'I' },
			{ 9, 'J' },
			{ 10, 'K' },
			{ 11, 'L' },
			{ 12, 'M' },
			{ 13, 'N' },
			{ 14, 'O' },
			{ 15, 'P' },
			{ 16, 'Q' },
			{ 17, 'R' },
			{ 18, 'S' },
			{ 19, 'T' },
			{ 20, 'U' },
			{ 21, 'V' },
			{ 22, 'W' },
			{ 23, 'X' },
			{ 24, 'Y' },
			{ 25, 'Z' },
		};


#else
		const std::map<fs::file_type, std::string> kTypeNames{
			{ fs::regular_file, "regular" },
			{ fs::directory_file, "directory" },
			{ fs::symlink_file, "symlink" },
			{ fs::block_file, "block" },
			{ fs::character_file, "character" },
			{ fs::fifo_file, "fifo" },
			{ fs::socket_file, "socket" },
			{ fs::type_unknown, "unknown" },
			{ fs::status_error, "error" },
		};

#endif

		void genFileInfo(const fs::path& path,
			const fs::path& parent,
			const std::string& pattern,
			QueryData& results) {
			// Must provide the path, filename, directory separate from boost path->string
			// helpers to match any explicit (query-parsed) predicate constraints.

#if defined(WIN32)

			DWORD dwRtnCode = 0;
			PSID pSidOwner = NULL;
			BOOL bRtnBool = TRUE;
			SID_NAME_USE eUse = SidTypeUnknown;
			HANDLE hFile;
			PSECURITY_DESCRIPTOR pSD = NULL;

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

			// Times
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
			}
			else {
				r["type"] = "unknown";
			}

#else	

			// Get the handle of the file object.
			hFile = CreateFile(
				TEXT(path.string().c_str()),
				GENERIC_READ,
				FILE_SHARE_READ,
				NULL,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				NULL);

			// Check GetLastError for CreateFile error code.
			if (hFile == INVALID_HANDLE_VALUE) {
				return;
			}

			// Get the owner SID of the file.
			dwRtnCode = GetSecurityInfo(
				hFile,
				SE_FILE_OBJECT,
				OWNER_SECURITY_INFORMATION,
				&pSidOwner,
				NULL,
				NULL,
				NULL,
				&pSD);

			// Check GetLastError for GetSecurityInfo error condition.
			if (dwRtnCode != ERROR_SUCCESS) {
				return;
			}

			FILE_BASIC_INFO basicInfo;
			BY_HANDLE_FILE_INFORMATION fileInfo;

			if (0 == GetFileInformationByHandle(hFile, &fileInfo))
			{
				return;
			}
			
			r["attrib"] = getFileAttribStr(fileInfo.dwFileAttributes);

			auto fileIndex = ((unsigned long long)fileInfo.nFileIndexHigh << 32) + (unsigned long long)fileInfo.nFileIndexLow;


			std::stringstream stream;
			stream << "0x" << std::setfill('0') << std::setw(sizeof(unsigned long long) * 2) << std::hex << fileIndex;
			std::string fileId(stream.str());

			// Windows has fileid's that are displayed in hex using: fsutil file queryfileid <filename>
			r["fileId"] = TEXT(fileId);

			// inode is the decimal equivalent of fileid
			r["inode"] = BIGINT(fileIndex);
			r["uid"] = INTEGER(getUidFromSid(pSidOwner));
			r["gid"] = INTEGER(getGidFromSid(pSidOwner));

			// Permission bits don't make sense for Windows. Use ntfs_acl_permissions table
			r["mode"] = "-1";


			if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				r["type"] = "directory";
			}
			else {

				auto dwfileType = GetFileType(hFile);
				if (kTypeNames.count(dwfileType)) {
					r["type"] = kTypeNames.at(dwfileType);
				}
				else {

					r["type"] = "unknown";
				}
			}

			std::stringstream volumeSerial;
			volumeSerial << std::hex << std::setfill('0') << std::setw(4) << HIWORD(fileInfo.dwVolumeSerialNumber) << "-" << std::setw(4) << LOWORD(fileInfo.dwVolumeSerialNumber);
			

			r["device"] = BIGINT(fileInfo.dwVolumeSerialNumber);
			r["volume_serial"] = TEXT(volumeSerial.str());

			LARGE_INTEGER li = { 0 };
			(GetFileSizeEx(hFile, &li) == 0) ? r["size"] = BIGINT(-1) : r["size"] = BIGINT(li.QuadPart);
			
			char *pszDrive = NULL;
			char szDrive[4];
			int nDriveLetterIndex = PathGetDriveNumber(path.string().c_str());

			r["block_size"] = INTEGER(-1);
			if (nDriveLetterIndex != -1)
			{

				if (kDriveLetters.count(nDriveLetterIndex)) {

					szDrive[0] = kDriveLetters.at(nDriveLetterIndex);
					szDrive[1] = ':';
					szDrive[2] = '\\';
					szDrive[3] = '\0';
					pszDrive = szDrive;

					DWORD	dwSectPerClus;
					DWORD 	dwBytesPerSect;
					DWORD 	dwFreeClusters;
					DWORD 	dwTotalClusters;

					if (GetDiskFreeSpace(pszDrive, &dwSectPerClus, &dwBytesPerSect,
						&dwFreeClusters, &dwTotalClusters)) 
					{
						r["block_size"] = INTEGER(dwBytesPerSect);
					}

				}
	
			}
			
			

			r["hard_links"] = INTEGER(fileInfo.nNumberOfLinks);

			// Times
			r["atime"] = BIGINT(FileTimeToUnixTime(fileInfo.ftLastAccessTime));
			r["mtime"] = BIGINT(FileTimeToUnixTime(fileInfo.ftLastWriteTime));
			r["btime"] = BIGINT(FileTimeToUnixTime(fileInfo.ftCreationTime));

			// Change time is not available in GetFileInformationByHandle
			bRtnBool = GetFileInformationByHandleEx(hFile,
				FileBasicInfo,
				&basicInfo,
				sizeof(basicInfo));

			(!bRtnBool) ? r["ctime"] = BIGINT(-1) : r["ctime"] = BIGINT(LongIntToUnixTime(basicInfo.ChangeTime));


			CloseHandle(hFile);

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
				}
				catch (const fs::filesystem_error& /* e */) {
					continue;
				}
			}

			return results;
		}
	}
}
