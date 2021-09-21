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
struct RegTableValueData {
  std::string key_name;
  std::string key_data;
};
struct RegTableData {
  std::string key;
  std::string key_path;
  std::string key_name;
  int64_t modified_time;
  std::string key_type;
  std::string key_data;
  std::vector<RegTableValueData> key_data_array;
};

struct RegNameKey {
  short sig;
  short flags;
  FILETIME timestamp;
  int unknown;
  int parent_key_offset;
  int number_sub_keys;
  int number_volatile_sub_keys;
  int sub_key_list_offset;
  int volatile_sub_key_list_offset;
  int number_values;
  int value_list_offset;
  int security_key_offset;
  int class_offset;
  int largest_sub_key_name_size;
  int largest_sub_key_class_name_size;
  int largest_value_name_size;
  int largest_value_data_size;
  int unknown2;
  short key_name_size;
  short class_name_size;
};

/**
 * @brief Windows helper function for parsing raw Registry files
 *
 * @returns The parsed Registry data
 */
std::vector<RegTableData> rawRegistry(const std::string& reg_path,
                                      const std::string& drive_path);

/**
 * @brief Windows helper function for parsing raw Registry cells
 *
 */
void parseHiveCell(const std::vector<char>& reg_contents,
                   const int& hive_offset,
                   std::vector<RegTableData>& raw_reg,
                   std::vector<std::string>& key_path,
                   const RegNameKey& name_key);
} // namespace osquery