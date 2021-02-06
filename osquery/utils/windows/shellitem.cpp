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
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include <string>
#include <vector>

#include <iostream>

struct ShellFileEntryData {
  std::string path;
  long long dos_created;
  long long dos_accessed;
  long long dos_modified;
  int ext_size;
  int version;
  std::string extension_sig;
  std::string identifier;
  long long mft_entry;
  int mft_sequence;
  int string_size;
};

const std::string kNetworkShareIds[6] = {"41", "42", "46", "47", "4C", "C3"};

// Only 0400EFBE and 2600EFBE have been widely seen
const std::string kShellItemExtensions[23] = {
    "0400EFBE", "0000EFBE", "0100EFBE", "0200EFBE", "0300EFBE", "0500EFBE",
    "0600EFBE", "0800EFBE", "0900EFBE", "0A00EFBE", "0B00EFBE", "0C00EFBE",
    "0e00EFBE", "1000EFBE", "1300EFBE", "1400EFBE", "1600EFBE", "1700EFBE",
    "1900EFBE", "1A00EFBE", "2100EFBE", "2500EFBE", "2600EFBE"};

// property sets/GUIDs associated with name entries?
const std::string kPropertySets[15] = {"000214A1-0000-0000-C000-000000000046",
                                       "01A3057A-74D6-4E80-BEA7-DC4C212CE50A",
                                       "46588AE2-4CBC-4338-BBFC-139326986DCE",
                                       "4D545058-4FCE-4578-95C8-8698A9BC0F49",
                                       "56A3372E-CE9C-11D2-9F0E-006097C686F6",
                                       "6444048F-4C8B-11D1-8B70-080036B11A03",
                                       "64440490-4C8B-11D1-8B70-080036B11A03",
                                       "64440491-4C8B-11D1-8B70-080036B11A03",
                                       "64440492-4C8B-11D1-8B70-080036B11A03",
                                       "8F052D93-ABCA-4FC5-A5AC-B01DF4DBE598",
                                       "B725F130-47EF-101A-A5F1-02608C9EEBAC",
                                       "D5CDD502-2E9C-101B-9397-08002B2CF9AE",
                                       "D5CDD505-2E9C-101B-9397-08002B2CF9AE",
                                       "EF6B490D-5CD8-437A-AFFC-DA8B60EE4A3C",
                                       "F29F85E0-4FF9-1068-AB91-08002B27B3D9"};
namespace osquery {
std::string guidParse(const std::string& guid_little) {
  std::vector<std::string> guids;
  guids.push_back(guid_little.substr(0, 8));
  guids.push_back(guid_little.substr(8, 4));
  guids.push_back(guid_little.substr(12, 4));

  std::string guid_4 = guid_little.substr(16, 4);
  std::string guid_5 = guid_little.substr(20, 12);

  // The first 16 GUID characters are in litte endian format
  for (auto& guid : guids) {
    std::reverse(guid.begin(), guid.end());
    for (std::size_t i = 0; i < guid.length(); i += 2) {
      std::swap(guid[i], guid[i + 1]);
    }
  }
  std::string guid_string =
      guids[0] + "-" + guids[1] + "-" + guids[2] + "-" + guid_4 + "-" + guid_5;
  return guid_string;
}

ShellFileEntryData fileEntry(const std::string& shell_data) {
  // check shellitem extension version
  size_t offset;
  std::string extension_sig;
  size_t entry_offset = 0;
  if (shell_data.find("0400EFBE") != std::string::npos) {
    offset = shell_data.find("0400EFBE");
    // std::cout << "Found a shellitem extension!. Sig is: " << "0400EFBE" <<
    // std::endl;
    extension_sig = shell_data.substr(offset, 8);
    entry_offset = offset - 8;
  } else if (shell_data.find("2600EFBE") != std::string::npos) {
    offset = shell_data.find("2600EFBE");
    extension_sig = shell_data.substr(offset, 8);
    entry_offset = offset - 8;
  }
  /*
  for (const auto& ext : kShellItemExtensions) {
    offset = shell_data.find(ext);
    if (offset != std::string::npos) {
      extension_sig = shell_data.substr(offset, 8);
      entry_offset = offset - 8;
    }
  }*/
  ShellFileEntryData file_entry;
  std::string version = shell_data.substr(entry_offset + 4, 4);
  // swap endianess
  std::reverse(version.begin(), version.end());
  for (std::size_t i = 0; i < version.length(); i += 2) {
    std::swap(version[i], version[i + 1]);
  }
  file_entry.version = std::stoi(version, nullptr, 16);
  if (file_entry.version < 7 && file_entry.version != 1) {
    LOG(WARNING)
        << "Shellitem format unsupported. Expecting version 1 or version 7 or "
           "higher, got version: "
        << file_entry.version;
    std::cout << shell_data << std::endl;
    file_entry.version = 0;
    return file_entry;
  }
  file_entry.extension_sig = shell_data.substr(entry_offset + 8, 8);

  // May contain Users Files folder, modified time is at offset 0x18 
  std::string timestamp = "";
  if (shell_data.find("43465346") != std::string::npos) {
    timestamp = shell_data.substr(36, 8);
    file_entry.dos_modified =
        (timestamp == "00000000")
            ? 0LL
            : parseFatTime(
                  timestamp);
  } else {
    timestamp = shell_data.substr(16, 8);
    file_entry.dos_modified =
        (timestamp == "00000000") ? 0LL : parseFatTime(timestamp);
  }
  timestamp = shell_data.substr(entry_offset + 16, 8);
  file_entry.dos_created =
      (timestamp == "00000000") ? 0LL : parseFatTime(timestamp);
  timestamp = shell_data.substr(entry_offset + 24, 8);
  file_entry.dos_accessed =
      (timestamp == "00000000") ? 0LL : parseFatTime(timestamp);
  // std::cout << "Parsed timestamps" << std::endl;
  file_entry.identifier = shell_data.substr(entry_offset + 32, 4);
  std::string mft_entry = shell_data.substr(entry_offset + 40, 12);
  // swap endianess
  std::reverse(mft_entry.begin(), mft_entry.end());
  for (std::size_t i = 0; i < mft_entry.length(); i += 2) {
    std::swap(mft_entry[i], mft_entry[i + 1]);
  }
  if (mft_entry == "000000000000") {
    file_entry.mft_entry = 0LL;
  } else {
    file_entry.mft_entry = std::stoll(mft_entry, nullptr, 16);
  }

  std::string mft_sequence = shell_data.substr(entry_offset + 52, 4);
  std::reverse(mft_sequence.begin(), mft_sequence.end());
  for (std::size_t i = 0; i < mft_sequence.length(); i += 2) {
    std::swap(mft_sequence[i], mft_sequence[i + 1]);
  }
  if (mft_sequence == "0000") {
    file_entry.mft_sequence = 0LL;
  } else {
    file_entry.mft_sequence = std::stoi(mft_sequence, nullptr, 16);
  }

  std::string string_size = shell_data.substr(entry_offset + 72, 4);
  // std::cout << "String size is: " << string_size << std::endl;
  std::reverse(string_size.begin(), string_size.end());
  for (std::size_t i = 0; i < string_size.length(); i += 2) {
    std::swap(string_size[i], string_size[i + 1]);
  }
  // NOT USING STRING SIZE FOR ANYTHING???
  file_entry.string_size = std::stoi(string_size, nullptr, 16);
  std::string entry_name = shell_data.substr(entry_offset + 92);
  // std::cout << "ENTRY name: " << entry_name << std::endl;

  // path name ends with 0000 (end of string)
  size_t name_end = entry_name.find("0000");
  std::string shell_name = entry_name.substr(0, name_end);
  // Path is in unicode, extra 00
  boost::erase_all(shell_name, "00");

  // is this really needed???
  // verify the the hex string length is even. This fixes issues with 10 base
  // hex values Example 7000690070000000... (pip)
  if (shell_name.length() % 2 != 0) {
    shell_name += "0";
  }
  std::string name;

  // Convert hex path to readable string
  try {
    name = boost::algorithm::unhex(shell_name);
  } catch (const boost::algorithm::hex_decode_error& /* e */) {
    LOG(WARNING) << "Failed to decode ShellItem path hex values to string: "
                 << shell_name;
  }
  // std::cout << shell_data << std::endl;
  file_entry.path = name;
  return file_entry;
}

// returns property store name or GUID/id if name not found
std::string propertyStore(const std::string& shell_data,
                          const std::vector<size_t>& wps_list) {
  std::string guid_string;
  for (const auto& offsets : wps_list) {
    std::string guid_little = shell_data.substr(offsets + 8, 32);
    std::string guid_string = guidParse(guid_little);
    for (const auto& property_list : kPropertySets) {
      if (guid_string != property_list) {
        continue;
      }
      std::string name_size = shell_data.substr(offsets + 48, 8);
      // std::cout << name_size << std::endl;
      std::reverse(name_size.begin(), name_size.end());
      for (std::size_t i = 0; i < name_size.length(); i += 2) {
        std::swap(name_size[i], name_size[i + 1]);
      }
      unsigned int size = std::stoi(name_size, nullptr, 16);
      std::string name = shell_data.substr(offsets + 74, (size + 1) * 4);
      // Convert hex path to readable string
      try {
        name = boost::algorithm::unhex(name);
      } catch (const boost::algorithm::hex_decode_error& /* e */) {
        LOG(WARNING) << "Failed to decode ShellItem path hex values to string: "
                     << name;
        return guid_string;
      }
      return name;
    }
  }
  return guid_string;
}

std::string networkShareItem(const std::string& bag_entry) {
  for (const auto& net_id : kNetworkShareIds) {
    // std::cout << bag_entry.substr(4, 2) << std::endl;
    if (net_id == bag_entry.substr(4, 2)) {
      // std::cout << net_id << std::endl;
      // std::cout << "network id match!" << std::endl;
      // subtract 10 from the final offset from find <--explain better :)
      std::string network_path =
          bag_entry.substr(10, bag_entry.find("00", 10) - 10);
      std::cout << network_path << std::endl;
      std::string name;
      try {
        name = boost::algorithm::unhex(network_path);
      } catch (const boost::algorithm::hex_decode_error& /* e */) {
        LOG(WARNING) << "Failed to decode ShellItem path hex values to string: "
                     << bag_entry;
        // std::string full_path = "";
        // for (const auto& path : build_shellbag) {
        //  full_path += path;
        //}
        // full_path.pop_back();
        // full_path += "[UNKNOWN SHELL ITEM]";
        // r["path"] = full_path;
        // results.push_back(r);
        return "[UNKNOWN NETWORK SHELL ITEM]";
      }
      return name + "\\";
      /*
      build_shellbag.push_back(name + "\\");
      std::string full_path = "";
      for (const auto& path : build_shellbag) {
        full_path += path;
      }
      std::cout << full_path << std::endl;
      full_path.pop_back();

      // network share paths do not have timestamps or MFT data
      r["path"] = full_path;
      results.push_back(r);
      parseShellEntries(key_path->second, build_shellbag, results);
      build_shellbag.pop_back();
      return;
      */
    }
  }
  return "";
}

std::string zipContentItem(const std::string& shell_data) {
  // std::cout << shell_data << std::endl;
  // std::cout << shell_data.substr(168, 2) << std::endl;
  int path_size = std::stoi(shell_data.substr(168, 2), nullptr, 16);

  // Zip folders can go down a max of two directories
  int second_path_size = std::stoi(shell_data.substr(176, 2), nullptr, 16);
  std::string path = shell_data.substr(184, path_size * 4);
  // Path is in unicode, extra 00
  boost::erase_all(path, "00");
  // Convert hex path to readable string
  try {
    path = boost::algorithm::unhex(path);
  } catch (const boost::algorithm::hex_decode_error& /* e */) {
    LOG(WARNING) << "Failed to decode ShellItem path hex values to string: "
                 << path;
    return "[PATH DECODE ERROR]";
  }
  if (second_path_size != 0) {
    path += "/";
    std::string second_path = shell_data.substr(200, second_path_size * 4);
    boost::erase_all(second_path, "00");
    // Convert hex path to readable string
    try {
      second_path = boost::algorithm::unhex(second_path);
      path += second_path;
    } catch (const boost::algorithm::hex_decode_error& /* e */) {
      LOG(WARNING) << "Failed to decode ShellItem path hex values to string: "
                   << second_path;
      path += "[PATH DECODE ERROR]";
      return path;
    }
  }
  // std::cout << path << std::endl;
  return path;
}

std::string rootFolderItem(const std::string& shell_data) {
  std::string guid_little = shell_data.substr(8, 32);
  std::string guid_string = guidParse(guid_little);
  return guid_string;
}

std::string driveLetterItem(const std::string& shell_data) {
  std::string volume;
  // Convert hex path to readable string
  try {
    volume = boost::algorithm::unhex(shell_data.substr(6, 6));
  } catch (const boost::algorithm::hex_decode_error& /* e */) {
    LOG(WARNING) << "Failed to decode Shellbag hex values to string: "
                 << shell_data;
    return "[UNKNOWN DRIVE VOLUME]";
  }
  return volume;
}

std::string controlPanelCategoryItem(const std::string& shell_data) {
  std::string panel_id = shell_data.substr(16, 2);
  // std::cout << "Panel id is: " << panel_id << std::endl;
  if (panel_id == "00") {
    return "All Control Panel Items"; // <---- is this right/??
  } else if (panel_id == "01") {
    return "Appearence and Personalization";
  } else if (panel_id == "02") {
    return "Hardware and Sound";
  } else if (panel_id == "03") {
    return "Network and Internet";
  } else if (panel_id == "04") {
    return "Sound, Speech, and Audio Devices";
  } else if (panel_id == "05") {
    return "System and Security";
  } else if (panel_id == "06") {
    return "Clock, Language, and Region";
  } else if (panel_id == "07") {
    return "Ease of Access";
  } else if (panel_id == "08") {
    return "Programs";
  } else if (panel_id == "09") {
    return "User Accounts";
  } else if (panel_id == "10") {
    return "Security Center";
  } else if (panel_id == "11") {
    return "Mobile PC";
  } else {
    LOG(WARNING) << "Unknown panel category: " << shell_data;
    return "[UNKNOWN PANEL CATEGORY]";
  }
}

std::string controlPanelItem(const std::string& shell_data) {
  std::string guid_little = shell_data.substr(28, 32);
  std::string guid_string = guidParse(guid_little);
  return guid_string;
}

ShellFileEntryData opticalDiscItem(const std::string& shell_data) {
  // check shellitem extension version
  size_t offset;
  std::string extension_sig;
  size_t entry_offset = 0;
  ShellFileEntryData file_entry;
  offset = shell_data.find("0400EFBE");
  if (offset == std::string::npos) {
    LOG(WARNING) << "Shellitem format unsupported. Did not find expected shell "
                    "extension";
    std::cout << shell_data << std::endl;
    file_entry.version = 0;
    return file_entry;
  }
  extension_sig = shell_data.substr(offset, 8);
  entry_offset = offset - 8;

  std::string version = shell_data.substr(entry_offset + 4, 4);
  std::cout << "Parsing optical file entry!" << std::endl;
  // swap endianess
  std::reverse(version.begin(), version.end());
  for (std::size_t i = 0; i < version.length(); i += 2) {
    std::swap(version[i], version[i + 1]);
  }
  file_entry.version = std::stoi(version, nullptr, 16);
  if (file_entry.version < 7 && file_entry.version != 1) {
    LOG(WARNING)
        << "Shellitem format unsupported. Expecting version 1 or version 7 or "
           "higher, got version: "
        << file_entry.version;
    std::cout << shell_data << std::endl;
    file_entry.version = 0;
    return file_entry;
  }
  file_entry.extension_sig = shell_data.substr(entry_offset + 8, 8);
  file_entry.dos_modified = parseFatTime(shell_data.substr(16, 8));
  file_entry.dos_created =
      parseFatTime(shell_data.substr(entry_offset + 16, 8));
  file_entry.dos_accessed =
      parseFatTime(shell_data.substr(entry_offset + 24, 8));
  file_entry.identifier = shell_data.substr(entry_offset + 32, 4);
  std::string mft_entry = shell_data.substr(entry_offset + 40, 12);
  // swap endianess
  std::reverse(mft_entry.begin(), mft_entry.end());
  for (std::size_t i = 0; i < mft_entry.length(); i += 2) {
    std::swap(mft_entry[i], mft_entry[i + 1]);
  }
  // std::cout << "MFT entry: " << mft_entry << std::endl;
  file_entry.mft_entry = std::stoll(mft_entry, nullptr, 16);

  std::string mft_sequence = shell_data.substr(entry_offset + 52, 4);
  std::reverse(mft_sequence.begin(), mft_sequence.end());
  for (std::size_t i = 0; i < mft_sequence.length(); i += 2) {
    std::swap(mft_sequence[i], mft_sequence[i + 1]);
  }
  file_entry.mft_sequence = std::stoi(mft_sequence, nullptr, 16);

  std::string string_size = shell_data.substr(entry_offset + 72, 4);
  // std::cout << "String size is: " << string_size << std::endl;
  std::reverse(string_size.begin(), string_size.end());
  for (std::size_t i = 0; i < string_size.length(); i += 2) {
    std::swap(string_size[i], string_size[i + 1]);
  }
  // NOT USING STRING SIZE FOR ANYTHING???
  file_entry.string_size = std::stoi(string_size, nullptr, 16);
  std::string entry_name = shell_data.substr(entry_offset + 92);
  std::cout << "eNTRY name: " << entry_name << std::endl;

  // path name ends with 0000 (end of string)
  size_t name_end = entry_name.find("0000");
  std::string shell_name = entry_name.substr(0, name_end);
  // Path is in unicode, extra 00
  boost::erase_all(shell_name, "00");

  // is this really needed???
  // verify the the hex string length is even. This fixes issues with 10 base
  // hex values Example 7000690070000000... (pip)
  if (shell_name.length() % 2 != 0) {
    shell_name += "0";
  }
  std::string name;

  // Convert hex path to readable string
  try {
    name = boost::algorithm::unhex(shell_name);
  } catch (const boost::algorithm::hex_decode_error& /* e */) {
    LOG(WARNING) << "Failed to decode ShellItem path hex values to string: "
                 << shell_name;
  }
  std::cout << shell_data << std::endl;
  std::cout << name << std::endl;
  file_entry.path = name;

  return file_entry;
}

std::vector<std::string> ftpItem(const std::string& shell_data) {
  std::vector<std::string> ftp_data;
  std::string access_time =
      shell_data.substr(28, 16); // shell data contains connection time
  // std::cout << access_time << std::endl;
  ftp_data.push_back(access_time);
  // find end of string
  size_t offset = shell_data.find("00", 92);
  size_t hostname_size = offset - 92;
  std::string ftp_hostname = shell_data.substr(92, hostname_size);
  // std::cout << ftp_hostname << std::endl;
  std::string name;
  try {
    name = boost::algorithm::unhex(ftp_hostname);
  } catch (const boost::algorithm::hex_decode_error& /* e */) {
    LOG(WARNING) << "Failed to decode ShellItem path hex values to string: "
                 << shell_data;
    ftp_data.push_back("[UNKNOWN NAME]");
  }
  ftp_data.push_back(name);
  return ftp_data;
}
} // namespace osquery