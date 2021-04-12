/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/system/system.h>

#include <string>
#include <vector>

namespace osquery {

struct ShellFileEntryData {
  std::string path;
  long long dos_created;
  long long dos_accessed;
  long long dos_modified;
  int version;
  std::string extension_sig;
  std::string identifier;
  long long mft_entry;
  int mft_sequence;
  int string_size;
};

/**
 * @brief Windows helper function for parsing file entry shell items
 *
 * @returns The file entry data structure
 */
ShellFileEntryData fileEntry(const std::string& shell_data);

/**
 * @brief Windows helper function for parsing Windows Property lists
 *
 * @returns The Windows Property List GUID name or GUID value
 */
std::string propertyStore(const std::string& shell_data,
                          const std::vector<size_t>& wps_list);

/**
 * @brief Windows helper function for parsing netshare shell items
 *
 * @returns The network share name
 */
std::string networkShareItem(const std::string& shell_data);

/**
 * @brief Windows helper function for parsing zip content shell items
 *
 * @returns The zip content name
 */
std::string zipContentItem(const std::string& shell_data);

/**
 * @brief Windows helper function for parsing root folder shell items
 *
 * @returns The root folder name
 */
std::string rootFolderItem(const std::string& shell_data);

/**
 * @brief Windows helper function for parsing drive letter shell items
 *
 * @returns The drive name
 */
std::string driveLetterItem(const std::string& shell_data);

/**
 * @brief Windows helper function for parsing conrol panel category shell items
 *
 * @returns The control panel category name
 */
std::string controlPanelCategoryItem(const std::string& shell_data);

/**
 * @brief Windows helper function for parsing conrol panel shell items
 *
 * @returns The control panel name
 */
std::string controlPanelItem(const std::string& shell_data);

/**
 * @brief Windows helper function for parsing ftp shell items
 *
 * @returns The ftp hostname
 */
std::vector<std::string> ftpItem(const std::string& shell_data);

/**
 * @brief Windows helper function for parsing little endian guid data
 *
 * @returns GUID string in the proper order
 */
std::string guidParse(const std::string& guid_little);

/**
 * @brief Windows helper function for parsing user property drive data
 *
 * @returns The drive name
 */
std::string propertyViewDrive(const std::string& shell_data);

/**
 * @brief Windows helper function for parsing user variable GUID data
 *
 * @returns The GUID name or GUID
 */
std::string variableGuid(const std::string& shell_data);

/**
 * @brief Windows helper function for parsing variable FTP data
 *
 * @returns The ftp string
 */
std::string variableFtp(const std::string& shell_data);

/**
 * @brief Windows helper function for parsing MTP device data
 *
 * @returns The MTP device name
 */
std::string mtpDevice(const std::string& shell_data);

/**
 * @brief Windows helper function for parsing MTP folder name data
 *
 * @returns The MTP folder name
 */
std::string mtpFolder(const std::string& shell_data);

/**
 * @brief Windows helper function for parsing MTP root name data
 *
 * @returns The MTP root name
 */
std::string mtpRoot(const std::string& shell_data);
} // namespace osquery