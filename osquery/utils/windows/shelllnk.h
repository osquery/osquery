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

struct LinkFlags {
  bool has_target_id_list;
  bool has_link_info;
  bool has_name;
  bool has_relative_path;
  bool has_working_dir;
  bool has_arguments;
  bool has_icon_location;
  bool is_unicode;
  bool no_link_info;
  bool has_exp_string;
  bool separate_process;
  bool unused;
  bool has_darwin_id;
  bool run_as_user;
  bool has_icon;
  bool pid_alias;
  bool unused2;
  bool shim_layer;
  bool no_link_track;
  bool target_metadata;
  bool disable_link_path;
  bool disable_folder_tracking;
  bool disable_folder_alias;
  bool link_to_link;
  bool unalias_on_save;
  bool environment_path;
  bool local_id_for_unc_target;
  bool error;
};

struct LinkFileHeader {
  std::string header;
  std::string guid;
  LinkFlags flags;
  std::string file_attribute;
  long long creation_time;
  long long access_time;
  long long modified_time;
  long long file_size;
  std::string icon_index;
  std::string window_value;
  std::string hot_key;
};

struct TargetInfo {
  std::string root_folder;
  std::string control_panel;
  std::string control_panel_category;
  std::string path;
  long long mft_entry;
  int mft_sequence;
  std::string data;
  std::string property_guid;
};

struct LocationInfo {
  std::string type;
  std::string serial;
  std::string data;
  std::string local_path;
  std::string common_path;
  std::string share_name;
};

struct DataStringInfo {
  std::string description;
  std::string relative_path;
  std::string working_path;
  std::string arguments;
  std::string icon_location;
  std::string data;
};

struct ExtraDataTracker {
  std::string hostname;
  std::string droid_volume;
  std::string droid_file;
  std::string birth_droid_volume;
  std::string birth_droid_file;
};

/**
 * @brief Windows helper function for parsing shortcut header data
 *
 * @returns The shortcut header structure
 */
LinkFileHeader parseShortcutHeader(const std::string& header);

/**
 * @brief Windows helper function for parsing shortcut target data
 *
 * @returns The shortcut target structure
 */
TargetInfo parseTargetInfo(const std::string& target_info);

/**
 * @brief Windows helper function for parsing shortcut location data
 *
 * @returns The shortcut location structure
 */
LocationInfo parseLocationData(const std::string& location_data);

/**
 * @brief Windows helper function for parsing shortcut data string data
 *
 * @returns The shortcut data string structure
 */
DataStringInfo parseDataString(const std::string& data,
                               const bool unicode,
                               const bool description,
                               const bool relative_path,
                               const bool working_path,
                               const bool icon_location,
                               const bool command_args);

/**
 * @brief Windows helper function for parsing shortcut extra data tracker
 *
 * @returns The shortcut extra data tracker structure
 */
ExtraDataTracker parseExtraDataTracker(const std::string& data);
} // namespace osquery
