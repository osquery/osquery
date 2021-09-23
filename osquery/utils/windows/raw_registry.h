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

struct RegHiveBin {
  int sig;
  int offset;
  int size;
  int reserved;
  int reserved2;
  int64_t timestamp;
  int unknown;
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

/**
 * @brief Windows helper function for parsing Leaf Hash Registry cells
 *
 */
void parseHiveLeafHash(const std::vector<char>& reg_contents,
                       int& offset,
                       std::vector<RegTableData>& raw_reg,
                       std::vector<std::string>& key_path,
                       const RegNameKey& name_key);

/**
 * @brief Windows helper function for parsing Leaf Index Registry cells
 *
 */
void parseHiveLeafIndex(const std::vector<char>& reg_contents,
                        int& offset,
                        std::vector<RegTableData>& raw_reg,
                        std::vector<std::string>& key_path,
                        const RegNameKey& name_key);

/**
 * @brief Windows helper function for parsing list of Value Key Registry cells
 *
 */
void parseValueKeyList(const std::vector<char>& reg_contents,
                       const int& num_values,
                       const int& offset,
                       std::vector<RegTableData>& raw_reg,
                       std::vector<std::string>& key_path,
                       const RegNameKey& name_key);

/**
 * @brief Windows helper function for parsing Registry Value key data
 *
 * @returns a string containing the Registry Value Key data
 */
std::string parseDataValue(const std::vector<char>& reg_contents,
                           const int& offset,
                           const int& size,
                           const std::string& reg_type);

/**
 * @brief Windows helper function for parsing Name Key Registry cells
 *
 */
void parseNameKey(const std::vector<char>& reg_contents,
                  int& offset,
                  std::vector<RegTableData>& raw_reg,
                  std::vector<std::string>& key_path);

/**
 * @brief Windows helper function for parsing Registry Value Key
 *
 */
void parseValueKey(const std::vector<char>& reg_contents,
                   const int& hive_bin_offset,
                   std::vector<RegTableData>& raw_reg,
                   std::vector<std::string>& key_path,
                   const RegNameKey& name_key);

/**
 * @brief Windows helper function for parsing Registry Big Data cells
 *
 */
void parseHiveBigData(const std::vector<char>& reg_contents,
                      const int& offset,
                      std::vector<RegTableData>& raw_reg,
                      std::vector<std::string>& key_path,
                      const RegNameKey& name_key);
/**
 * @brief Windows helper function for getting Registry Security Key cells
 *
 */
void parseHiveSecurityKey(const std::vector<char>& reg_contents,
                          const int& offset,
                          std::vector<RegTableData>& raw_reg,
                          std::vector<std::string>& key_path,
                          const RegNameKey& name_key);
/**
 * @brief Windows helper function for parsing Registry Hive Bins
 *
 * @returns RegHiveBin struct containing the Hive Bin data
 */
RegHiveBin parseHiveBin(const std::vector<char>& reg_contents,
                        const int& offset);

/**
 * @brief Windows helper function for formatting paths for Sleuthkit
 *
 */
void cleanRegPath(std::string& reg_path);

} // namespace osquery