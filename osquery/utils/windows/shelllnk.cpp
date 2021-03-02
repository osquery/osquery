/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/windows/shellitem.h>

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>

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
  std::string path;
  long long mft_entry;
  int mft_sequence;
  std::string data;
};

struct LocationInfo {
  std::string type;
  std::string serial;
  std::string device;
  std::string name;
  std::string provider_type;
  std::string data;
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

namespace osquery {
LinkFlags parseShortcutFlags(const std::string& flags) {
  // std::cout << "Parsing flags!" << std::endl;
  std::string flags_swap = swapEndianess(flags);
  int flags_int = std::stoi(flags_swap, nullptr, 16);
  LinkFlags lnk_flags;
  lnk_flags.has_target_id_list = (bool)(flags_int & 0x1);
  lnk_flags.has_link_info = (bool)(flags_int & 0x2);
  lnk_flags.has_name = (bool)(flags_int & 0x4);
  lnk_flags.has_relative_path = (bool)(flags_int & 0x8);
  lnk_flags.has_working_dir = (bool)(flags_int & 0x10);
  lnk_flags.has_arguments = (bool)(flags_int & 0x20);
  lnk_flags.has_icon_location = (bool)(flags_int & 0x40);
  lnk_flags.is_unicode = (bool)(flags_int & 0x80);
  lnk_flags.no_link_info = (bool)(flags_int & 0x100);
  lnk_flags.has_exp_string = (bool)(flags_int & 0x200);
  lnk_flags.separate_process = (bool)(flags_int & 0x400);
  lnk_flags.unused = (bool)(flags_int & 0x800);
  lnk_flags.has_darwin_id = (bool)(flags_int & 0x1000);
  lnk_flags.run_as_user = (bool)(flags_int & 0x2000);
  lnk_flags.has_icon = (bool)(flags_int & 0x4000);
  lnk_flags.pid_alias = (bool)(flags_int & 0x5000);
  lnk_flags.unused2 = (bool)(flags_int & 0x10000);
  lnk_flags.shim_layer = (bool)(flags_int & 0x20000);
  lnk_flags.no_link_track = (bool)(flags_int & 0x40000);
  lnk_flags.target_metadata = (bool)(flags_int & 0x80000);
  lnk_flags.disable_link_path = (bool)(flags_int & 0x100000);
  lnk_flags.disable_folder_tracking = (bool)(flags_int & 0x200000);
  lnk_flags.disable_folder_alias = (bool)(flags_int & 0x400000);
  lnk_flags.link_to_link = (bool)(flags_int & 0x800000);
  lnk_flags.unalias_on_save = (bool)(flags_int & 0x1000000);
  lnk_flags.environment_path = (bool)(flags_int & 0x2000000);
  lnk_flags.local_id_for_unc_target = (bool)(flags_int & 0x4000000);
  return lnk_flags;
}
LinkFileHeader parseShortcutHeader(const std::string& header) {
  // std::cout << "Parsing the header!" << std::endl;
  LinkFileHeader lnk_header;
  lnk_header.header = header.substr(0, 8);
  lnk_header.guid = header.substr(8, 32);
  std::string header_flags = header.substr(40, 8);
  lnk_header.flags = parseShortcutFlags(header_flags);
  lnk_header.file_attribute = header.substr(48, 8);
  std::string target_timestamp = header.substr(56, 16);
  if (target_timestamp == "0000000000000000") {
    lnk_header.creation_time = 0LL;
  } else {
    lnk_header.creation_time = littleEndianToUnixTime(target_timestamp);
  }
  target_timestamp = header.substr(72, 16);
  if (target_timestamp == "0000000000000000") {
    lnk_header.access_time = 0LL;
  } else {
    lnk_header.access_time = littleEndianToUnixTime(target_timestamp);
  }
  target_timestamp = header.substr(88, 16);
  if (target_timestamp == "0000000000000000") {
    lnk_header.modified_time = 0LL;
  } else {
    lnk_header.modified_time = littleEndianToUnixTime(target_timestamp);
  }
  std::string file_size_str = swapEndianess(header.substr(104, 8));

  lnk_header.file_size = std::stoll(file_size_str, nullptr, 16);
  lnk_header.icon_index = header.substr(112, 8);
  lnk_header.window_value = header.substr(120, 8);
  lnk_header.hot_key = header.substr(128, 4);
  return lnk_header;
}
TargetInfo parseTargetInfo(const std::string& target_info) {
  // std::cout << "Parsing target data!" << std::endl;
  // std::cout << target_info << std::endl;
  std::string data = target_info;
  TargetInfo target_lnk;
  std::vector<std::string> build_path;
  ShellFileEntryData file_entry;
  file_entry.mft_entry = 0LL;
  file_entry.mft_sequence = 0LL;
  // Loop through all the shellitems
  while (true) {
    std::string str_item_size = data.substr(0, 4);
    str_item_size = swapEndianess(str_item_size);
    int item_size = std::stoi(str_item_size, nullptr, 16) * 2;
    // Empty target item sizes will cause infinte loop, sometimes at the end of
    // the item there will be extra zeros
    if (item_size == 0) {
      break;
    }
    std::string sig = data.substr(4, 2);
    std::string sig_2 = data.substr(0, 2); // you shouldnt need this?????????
    std::string item_string = data.substr(0, item_size);
    if (sig == "1F") {
      // std::cout << "Root folder!" << std::endl;
      target_lnk.root_folder = rootFolderItem(item_string);
      build_path.push_back(target_lnk.root_folder);
      // std::cout << target_lnk.root_folder << std::endl;
      data.erase(0, item_size);
      // std::cout << data << std::endl;
      continue;
    } else if (sig == "31" || sig == "30" || sig == "32" || sig == "35" ||
               sig == "B1") {
      // std::cout << "File entry!" << std::endl;
      file_entry = fileEntry(item_string);
      build_path.push_back(file_entry.path);
      data.erase(0, item_size);
      // std::cout << data << std::endl;
      continue;
    } else if (sig == "2F" || sig == "23" || sig == "25" || sig == "29" ||
               sig == "2A" || sig == "2E") {
      // std::cout << "Drive entry!" << std::endl;
      if (item_string.substr(6, 2) == "80" || // <------------- review this
          (item_string.find("2600EFBE") != std::string::npos ||
           item_string.find("2500EFBE") !=
               std::string::npos)) { // Check if GUID exists
        // std::cout << "A GUID exists!" << std::endl;
        std::string guid_little = item_string.substr(8, 32);
        std::string guid_string = guidParse(guid_little);

        build_path.push_back("{" + guid_string + "}");
        data.erase(0, item_size);
        // std::cout << data << std::endl;
        continue;
      }
      std::string drive = driveLetterItem(item_string);
      // std::cout << drive << std::endl;
      drive.pop_back();
      build_path.push_back(drive);
      data.erase(0, item_size);
      // std::cout << data << std::endl;
      continue;
    } else if ((sig == "74" || sig_2 == "74") &&
               item_string.find("43465346") != std::string::npos) {
      // std::cout << "user property view!" << std::endl;
      file_entry = fileEntry(item_string);
      build_path.push_back(file_entry.path);
      data.erase(0, item_size);
      continue;
    } else if ((sig == "61" || sig_2 == "61")) {
      // std::cout << "FTP/URI entry!" << std::endl;
      std::vector<std::string> ftp_data = ftpItem(item_string);
      build_path.push_back(ftp_data[1]);
      data.erase(0, item_size);
      continue;
    } else if (sig == "00") { // Variable shell item, can contain a variety of
                              // shell item formats

      // std::cout << "Variable data" << std::endl;
      if (item_string.find("EEBBFE23") != std::string::npos) {
        // std::cout << "Variable guid entry!" << std::endl;

        std::string guid_string = variableGuid(item_string);
        // std::string guid_name = guidLookup(guid_string);
        build_path.push_back("{" + guid_string + "}");
        data.erase(0, item_size);
        continue;
      } else if (item_string.substr(12, 8) == "05000000" ||
                 item_string.substr(12, 8) == "05000300") {
        // std::cout << "FTP/URI variable entry!" << std::endl;

        std::string ftp_name = variableFtp(item_string);
        build_path.push_back(ftp_name);
        data.erase(0, item_size);
        // std::cout << data << std::endl;
        continue;
      }
    }

    break;
  }
  target_lnk.path = osquery::join(build_path, "\\");
  target_lnk.mft_entry = file_entry.mft_entry;
  target_lnk.mft_sequence = file_entry.mft_sequence;
  target_lnk.data = data;
  return target_lnk;
}
LocationInfo parseLocationData(const std::string& location_data) {
  // std::cout << "Parsing location data!" << std::endl;
  // std::cout << location_data << std::endl;
  LocationInfo location_info;
  std::string data = location_data.substr(4);
  std::string str_location_size = data.substr(0, 8);
  str_location_size = swapEndianess(str_location_size);
  int location_size = std::stoi(str_location_size, nullptr, 16) * 2;

  std::string location_type = data.substr(16, 8);
  location_type = swapEndianess(location_type);

  // Double check this!!!!
  if (location_type == "00000001") {
    std::string volume_offset = data.substr(24, 8);
    // std::cout << volume_offset << std::endl;
    volume_offset = swapEndianess(volume_offset);
    int offset = std::stoi(volume_offset, nullptr, 16);
    std::string type = data.substr((offset * 2) + 8, 8);
    if (type == "03000000") {
      location_info.type = "Fixed storage media (harddisk)";
    } else if (type == "00000000") {
      location_info.type = "Unknown";
    } else if (type == "01000000") {
      location_info.type = "No root directory";
    } else if (type == "04000000") {
      location_info.type = "Remote storage";
    } else if (type == "05000000") {
      location_info.type = "Optical disc (CD-ROM, DVD, BD)";
    } else if (type == "06000000") {
      location_info.type = "RAM drive";
    } else {
      location_info.type = "UNKNOWN VOLUME TYPE";
    }
    std::string serial = data.substr((offset * 2) + 16, 8);
    location_info.serial = swapEndianess(serial);
  } else if (location_type == "00000002") {
    location_info.type = "CommonNetworkRelativeLinkAndPathSuffix";
  } else {
    location_info.type = "UNKNOWN LOCATION TYPE";
  }
  data.erase(0, location_size);
  location_info.data = data;

  return location_info;
}
DataStringInfo parseDataString(const std::string& data,
                               bool unicode,
                               bool& description,
                               bool& relative_path,
                               bool& working_path,
                               bool& icon_location,
                               bool& command_args) {
  // std::cout << "Parsing data strings!" << std::endl;
  // std::cout << data << std::endl;
  std::string data_string = data;
  std::string data_str_type = "";
  DataStringInfo data_info;
  std::string str_data_size = data.substr(0, 4);
  str_data_size = swapEndianess(str_data_size);
  int data_size = std::stoi(str_data_size, nullptr, 16);
  if (description) {
    std::cout << "description" << std::endl;

    if (unicode) {
      data_size = data_size * 4;
    }
    data_str_type = data_string.substr(4, data_size);
    if (unicode) {
      boost::erase_all(data_str_type, "00");
    }
    try {
      data_info.description = boost::algorithm::unhex(data_str_type);
    } catch (const boost::algorithm::hex_decode_error& /* e */) {
      LOG(WARNING) << "Failed to decode Description hex values to string: "
                   << data_string;
    }
    data_string.erase(0, data_size + 4);
    str_data_size = data_string.substr(0, 4);
    str_data_size = swapEndianess(str_data_size);
    data_size = std::stoi(str_data_size, nullptr, 16);
    std::cout << data_string << std::endl;
  }
  if (relative_path) {
    // std::cout << "relative path" << std::endl;

    if (unicode) {
      data_size = data_size * 4;
    }
    data_str_type = data_string.substr(4, data_size);
    if (unicode) {
      boost::erase_all(data_str_type, "00");
    }
    try {
      data_info.relative_path = boost::algorithm::unhex(data_str_type);
    } catch (const boost::algorithm::hex_decode_error& /* e */) {
      LOG(WARNING) << "Failed to decode Relative Path hex values to string: "
                   << data_string;
    }
    data_string.erase(0, data_size + 4);
    str_data_size = data_string.substr(0, 4);
    str_data_size = swapEndianess(str_data_size);
    data_size = std::stoi(str_data_size, nullptr, 16);
  }
  if (working_path) {
    // std::cout << "Working path" << std::endl;
    if (unicode) {
      data_size = data_size * 4;
    }
    data_str_type = data_string.substr(4, data_size);
    if (unicode) {
      boost::erase_all(data_str_type, "00");
    }
    try {
      data_info.working_path = boost::algorithm::unhex(data_str_type);
    } catch (const boost::algorithm::hex_decode_error& /* e */) {
      LOG(WARNING) << "Failed to decode Working Path hex values to string: "
                   << data_string;
    }
    data_string.erase(0, data_size + 4);
    str_data_size = data_string.substr(0, 4);
    str_data_size = swapEndianess(str_data_size);
    data_size = std::stoi(str_data_size, nullptr, 16);
  }
  if (command_args) {
    std::cout << "command args" << std::endl;

    if (unicode) {
      data_size = data_size * 4;
    }
    data_str_type = data_string.substr(4, data_size);
    if (unicode) {
      boost::erase_all(data_str_type, "00");
    }
    try {
      data_info.arguments = boost::algorithm::unhex(data_str_type);
    } catch (const boost::algorithm::hex_decode_error& /* e */) {
      LOG(WARNING) << "Failed to decode Command args hex values to string: "
                   << data_string;
    }
    data_string.erase(0, data_size + 4);
    str_data_size = data_string.substr(0, 4);
    str_data_size = swapEndianess(str_data_size);
    data_size = std::stoi(str_data_size, nullptr, 16);
  }
  if (icon_location) {
    // std::cout << "Icon location" << std::endl;

    if (unicode) {
      data_size = data_size * 4;
    }
    data_str_type = data_string.substr(4, data_size);
    if (unicode) {
      boost::erase_all(data_str_type, "00");
    }
    try {
      data_info.icon_location = boost::algorithm::unhex(data_str_type);
    } catch (const boost::algorithm::hex_decode_error& /* e */) {
      LOG(WARNING) << "Failed to decode Icon Location hex values to string: "
                   << data_string;
    }
    data_string.erase(0, data_size + 4);
    str_data_size = data_string.substr(0, 4);
    str_data_size = swapEndianess(str_data_size);
    data_size = std::stoi(str_data_size, nullptr, 16);
  }
  data_info.data = data_string;
  return data_info;
}
ExtraDataTracker parseExtraDataTracker(const std::string& data) {
  ExtraDataTracker data_tracker;
  // std::cout << "Parsing extra data!" << std::endl;
  if (data.find("60000000") == std::string::npos &&
      data.find("030000A0") == std::string::npos) {
    // LOG(WARNING) << "Tracker database not found";
    data_tracker.hostname = "";
    return data_tracker;
  }
  std::string hostname = data.substr(32, 32);
  try {
    data_tracker.hostname = boost::algorithm::unhex(hostname);
  } catch (const boost::algorithm::hex_decode_error& /* e */) {
    LOG(WARNING) << "Failed to decode hostname hex values to string: " << data;
  }
  std::string guid = data.substr(64, 32);
  data_tracker.droid_volume = guidParse(guid);
  guid = data.substr(96, 32);
  data_tracker.droid_file = guidParse(guid);
  guid = data.substr(128, 32);
  data_tracker.birth_droid_volume = guidParse(guid);
  guid = data.substr(160, 32);
  data_tracker.birth_droid_file = guidParse(guid);
  return data_tracker;
}
} // namespace osquery