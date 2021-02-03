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
struct ShellFileEntryData {
  std::string path;
  long long dos_created;
  long long dos_accessed;
  long long dos_modified;
  int ext_size;
  int version;
  std::string extension_sig;
  std::string identifier;
  long mft_entry;
  int mft_sequence;
  int string_size;
};
namespace osquery {
ShellFileEntryData fileEntry(const std::string& shell_data);

// return property name if decoded or return guid string
std::string propertyStore(const std::string& shell_data,
                          const std::vector<size_t>& wps_list);

std::string networkShareItem(const std::string& shell_data);

std::string zipContentItem(const std::string& shell_data);

std::string rootFolderItem(const std::string& shell_data);

std::string driveLetterItem(const std::string& shell_data);

std::string controlPanelCategoryItem(const std::string& shell_data);

std::string controlPanelItem(const std::string& shell_data);
}