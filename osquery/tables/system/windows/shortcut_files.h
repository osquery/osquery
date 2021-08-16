/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/utils/windows/shelllnk.h>

#include <string>

namespace osquery {
namespace tables {

struct LnkData {
  LinkFileHeader header;
  TargetInfo target_data;
  LocationInfo location_data;
  ExtraDataTracker extra_data;
  DataStringInfo data_info_string;
  std::string target_path;
};

/**
 * @brief Windows helper function for parsing Shortcut files
 *
 * @returns Tabel results for shortcut files
 */
LnkData parseShortcutFiles(const LinkFileHeader& data,
                           const std::string& data_string);
} // namespace tables
} // namespace osquery