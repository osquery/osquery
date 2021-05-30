/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/tables/system/windows/registry.h>
#include <osquery/tables/system/windows/shortcut_files.h>
#include <osquery/utils/conversions/join.h>

#include <osquery/logger/logger.h>
#include <osquery/utils/windows/olecf.h>
#include <osquery/utils/windows/shelllnk.h>

#include <boost/filesystem.hpp>

#include <sstream>
#include <string>

#include <iostream>

namespace osquery {
namespace tables {
const std::string test_jump_file =
    "C:"
    "\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDesti"
    "nations"
    "\\f18460fded109990.automaticDestinations-ms";
const std::string auto_jumps_location = "\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDesti"
    "nations"
    "\\";
void parseJumplistFiles(QueryData& results,
                        const LinkFileHeader& data,
                        const JumplistData& jump_data,
                        const std::string& path) {
  LnkData data_lnk;
  const int lnk_data = 152;

  data_lnk = parseShortcutFiles(data, jump_data.lnk_data.substr(lnk_data));

  Row r;
  r["path"] = path;
  r["target_created"] = INTEGER(data.creation_time);
  r["target_modified"] = INTEGER(data.modified_time);
  r["target_accessed"] = INTEGER(data.access_time);
  r["target_size"] = BIGINT(data.file_size);

  if (data.flags.has_target_id_list) {
    r["target_path"] = data_lnk.target_path;
    if (data_lnk.target_data.mft_entry != -1LL) {
      r["mft_entry"] = BIGINT(data_lnk.target_data.mft_entry);
      r["mft_sequence"] = INTEGER(data_lnk.target_data.mft_sequence);
    }
  }
  if (data.flags.has_link_info) {
    r["local_path"] = data_lnk.location_data.local_path;
    r["common_path"] = data_lnk.location_data.common_path;
    r["device_type"] = data_lnk.location_data.type;
    r["volume_serial"] = data_lnk.location_data.serial;
    r["share_name"] = data_lnk.location_data.share_name;
  }
  if (data.flags.has_name || data.flags.has_relative_path ||
      data.flags.has_working_dir || data.flags.has_arguments ||
      data.flags.has_icon_location) {
    r["relative_path"] = data_lnk.data_info_string.relative_path;
    r["command_args"] = data_lnk.data_info_string.arguments;
    r["icon_path"] = data_lnk.data_info_string.icon_location;
    r["working_path"] = data_lnk.data_info_string.working_path;
    r["description"] = data_lnk.data_info_string.description;
  }
  r["hostname"] = data_lnk.extra_data.hostname;
  r["app_id"] = "GET FROM FILENAME";
  r["app_name"] = "PROVIDE JSON MAPPING";
  r["entry"] = INTEGER(jump_data.entry);
  r["interaction_count"] = INTEGER(jump_data.interaction_count);
  results.push_back(r);
}

QueryData genJumplists(QueryContext& context) {
  QueryData results;
  std::set<boost::filesystem::path> home_paths = getHomeDirectories();
  for (const auto& home : home_paths) {
    std::cout << home << std::endl;
    if (home.string().find("Users") == std::string::npos) {
      continue;
    }
    std::vector<std::string> auto_jump_files;
    std::string user_path = (home / auto_jumps_location).string();
    Status status = listFilesInDirectory(user_path, auto_jump_files);
    if (!status.ok()) {
      LOG(WARNING) << "Failed to get automatic Jumplist files";
      return results;
    }
    for (const auto& auto_files : auto_jump_files) {
      std::cout << auto_files << std::endl;
    }
  }
  boost::system::error_code ec;
  boost::filesystem::path path = test_jump_file;
  // if (!boost::filesystem::is_regular_file(path, ec)) {
  //   continue;
  // }
  std::ifstream input_file(path.string(), std::ios::in | std::ios::binary);
  std::vector<char> jump_data((std::istreambuf_iterator<char>(input_file)),
                              (std::istreambuf_iterator<char>()));
  input_file.close();

  std::vector<JumplistData> jumplist_data = parseOlecf(jump_data);
  for (const auto& entry : jumplist_data) {
    std::cout << "Starting jumplist parsing!" << std::endl;
    LinkFileHeader data;
    data = parseShortcutHeader(entry.lnk_data);
    if (data.header.empty()) {
      continue;
    }
    parseJumplistFiles(results, data, entry, test_jump_file);
  }

  // This can be used for custom jumplist files
  /*
  // Read the whole jumplist file
  lnk_content = "";
  if (!readFile(path, lnk_content).ok()) {
    LOG(WARNING) << "Failed to read jumplist file: " << test_jump_file;
   // continue;
  }
  std::stringstream ss;
  for (const auto& hex_char : lnk_content) {
    std::stringstream value;
    value << std::setfill('0') << std::setw(2);
    value << std::hex << std::uppercase << (int)(unsigned char)(hex_char);
    ss << value.str();
  }

  std::string lnk_hex = ss.str();
  while (true) {
    std::cout << "Starting jumplist parsing!" << std::endl;
    std::size_t jump_entry =
lnk_hex.find("004C0000000114020000000000C000000000000046"); if (jump_entry ==
std::string::npos) { break;
    }
    lnk_hex.erase(0, jump_entry+2);
    //std::cout << lnk_hex << std::endl;
    LinkFileHeader data;

    data = parseShortcutHeader(lnk_hex);
    if (data.header.empty()) {
      continue;
    }
    const int lnk_data = 152;
    std::string data_string = lnk_hex.substr(lnk_data);
    std::string lnk_path = test_jump_file;
    //parseJumplistFiles(results, data, data_string, lnk_path);
    std::cout << "finished parsing all entries!" << std::endl;
    lnk_hex.erase(0, 42);
  }
//}
*/
  return results;
}
} // namespace tables
} // namespace osquery