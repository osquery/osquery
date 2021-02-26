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
};

struct LinkFileHeader {
  std::string header;
  std::string guid;
  LinkFlags flags;
  std::string file_attribute;
  std::string creation_time;
  std::string access_time;
  std::string modified_time;
  std::string file_size;
  std::string icon_index;
  std::string window_value;
  std::string hot_key;
};

namespace osquery {
LinkFileHeader parseShortcutHeader(const std::string& header);
}