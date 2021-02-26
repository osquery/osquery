/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/windows/shellitem.h>

#include <iostream>
#include <sstream>
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
  bool error
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
LinkFlags parseShortcutFlags(const std::string& flags) {
  std::cout << "Parsing flags!" << std::endl;
  std::cout << flags << std::endl;
  std::string binary_string = "";
  LinkFlags lnk_flags;
  for (const auto& bin : flags) {
    switch (bin) {
    case '0':
      binary_string += "0000";
      break;
    case '1':
      binary_string += "0001";
      break;
    case '2':
      binary_string += "0010";
      break;
    case '3':
      binary_string += "0011";
      break;
    case '4':
      binary_string += "0100";
      break;
    case '5':
      binary_string += "0101";
      break;
    case '6':
      binary_string += "0110";
      break;
    case '7':
      binary_string += "0111";
      break;
    case '8':
      binary_string += "1000";
      break;
    case '9':
      binary_string += "1001";
      break;
    case 'a':
      binary_string += "1010";
      break;
    case 'b':
      binary_string += "1011";
      break;
    case 'c':
      binary_string += "1100";
      break;
    case 'd':
      binary_string += "1101";
      break;
    case 'e':
      binary_string += "1110";
      break;
    case 'f':
      binary_string += "1111";
      break;
    default:
      std::cout << "Non-hex value character" << std::endl;
      lnk_flags.error = true;
      return lnk_flags;
    }
  }
  std::cout << "Binary format is: " << binary_string << std::endl;
  lnk_flags.has_target_id_list = (bool)(int)binary_string[0];
  lnk_flags.has_link_info = (bool)(int)binary_string[1];
  lnk_flags.has_name = (bool)(int)binary_string[2];
  lnk_flags.has_relative_path = (bool)(int)binary_string[3];
  lnk_flags.has_working_dir = (bool)(int)binary_string[4];
  lnk_flags.has_arguments = (bool)(int)binary_string[5];
  lnk_flags.has_icon_location = (bool)(int)binary_string[6];
  lnk_flags.is_unicode = (bool)(int)binary_string[7];
  lnk_flags.has_exp_string = (bool)(int)binary_string[8];
  lnk_flags.separate_process = (bool)(int)binary_string[9];
  lnk_flags.unused = (bool)(int)binary_string[10];
  lnk_flags.has_darwin_id = (bool)(int)binary_string[11];
  lnk_flags.run_as_user = (bool)(int)binary_string[12];
  lnk_flags.has_icon = (bool)(int)binary_string[13];
  lnk_flags.pid_alias = (bool)(int)binary_string[14];
  lnk_flags.unused2 = (bool)(int)binary_string[15];
  lnk_flags.shim_layer = (bool)(int)binary_string[16];
  lnk_flags.no_link_track = (bool)(int)binary_string[17];
  lnk_flags.target_metadata = (bool)(int)binary_string[18];
  lnk_flags.disable_link_path = (bool)(int)binary_string[19];
  lnk_flags.disable_folder_tracking = (bool)(int)binary_string[20];
  lnk_flags.disable_folder_alias = (bool)(int)binary_string[21];
  lnk_flags.link_to_link = (bool)(int)binary_string[22];
  lnk_flags.unalias_on_save = (bool)(int)binary_string[23];
  lnk_flags.environment_path = (bool)(int)binary_string[24];
  lnk_flags.local_id_for_unc_target = (bool)(int)binary_string[25];
  std::cout << lnk_flags.has_target_id_list << std::endl;
  return lnk_flags;
}
		LinkFileHeader parseShortcutHeader(const std::string& header) {
          std::cout << "Parsing the header!" << std::endl;
                  LinkFileHeader lnk_header;
          lnk_header.header = header.substr(0, 8);
          lnk_header.guid = header.substr(8, 32);
          std::string header_flags = header.substr(40, 8);
          lnk_header.flags = parseShortcutFlags(header_flags);
          lnk_header.file_attribute = header.substr(48, 8);
          lnk_header.creation_time = header.substr(54, 16);
          lnk_header.access_time = header.substr(72, 16);
          lnk_header.modified_time = header.substr(88, 16);
          lnk_header.file_size = header.substr(104, 8);
          lnk_header.icon_index = header.substr(112, 8);
          lnk_header.window_value = header.substr(120, 8);
          lnk_header.hot_key = header.substr(128, 4);
          return lnk_header;
        }

		
	
}