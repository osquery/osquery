/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/windows/shellitem.h>

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>

#include <string>
#include <vector>

const std::string kNetworkShareIds[6] = {"41", "42", "46", "47", "4C", "C3"};

// Property set GUIDs associated with name entries
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
  size_t offset;
  std::string extension_sig;
  size_t entry_offset = 0;
  // Find "0400EFBE" offset
  if (shell_data.find("0400EFBE") != std::string::npos) {
    offset = shell_data.find("0400EFBE");
    extension_sig = shell_data.substr(offset, 8);
    entry_offset = offset - 8;
  }
  ShellFileEntryData file_entry;

  if (entry_offset <= 0) {
    LOG(WARNING)
        << "Could not find supported file entry extension in shell data: "
        << shell_data;
    file_entry.path = "[UNSUPPORTED SHELL EXTENSION]";
    return file_entry;
  }

  std::string version = shell_data.substr(entry_offset + 4, 4);
  version = swapEndianess(version);
  file_entry.version = tryTo<int>(version, 16).takeOr(0);
  if (file_entry.version < 7) {
    LOG(WARNING) << "Shellitem format unsupported. Expecting version 7 or "
                    "higher: "
                 << shell_data;
    file_entry.path = "[UNSUPPORTED SHELL EXTENSION]";
    return file_entry;
  }
  file_entry.extension_sig = extension_sig;

  // Shell data may contain Users Files folder signature, modified time is at
  // offset 0x18
  std::string timestamp = "";
  if (shell_data.find("43465346") != std::string::npos) {
    timestamp = shell_data.substr(36, 8);
    file_entry.dos_modified =
        (timestamp == "00000000") ? 0LL : parseFatTime(timestamp);
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
  file_entry.identifier = shell_data.substr(entry_offset + 32, 4);
  std::string ntfs_data = shell_data.substr(entry_offset + 40, 16);
  std::string mft_entry = ntfs_data.substr(0, 12);
  mft_entry = swapEndianess(mft_entry);

  if (mft_entry == "000000000000") {
    file_entry.mft_entry = 0LL;
  } else {
    file_entry.mft_entry = tryTo<long long>(mft_entry, 16).takeOr(0ll);
  }

  std::string mft_sequence = ntfs_data.substr(12, 4);
  mft_sequence = swapEndianess(mft_sequence);
  if (mft_sequence == "0000") {
    file_entry.mft_sequence = 0;
  } else {
    file_entry.mft_sequence = tryTo<int>(mft_sequence, 16).takeOr(0);
  }

  std::string string_size = shell_data.substr(entry_offset + 72, 4);
  string_size = swapEndianess(string_size);
  file_entry.string_size = tryTo<int>(string_size, 16).takeOr(0);
  int name_offset = 0;
  if (file_entry.version >= 9) {
    name_offset = 92;
  } else if (file_entry.version == 8) {
    name_offset = 84;
  } else if (file_entry.version == 7) {
    name_offset = 72;
  }
  std::string entry_name = shell_data.substr(entry_offset + name_offset);

  // path name ends with 0000 (end of string)
  size_t name_end = entry_name.find("0000");
  std::string shell_name = entry_name.substr(0, name_end);
  // Path is in unicode, extra 00
  boost::erase_all(shell_name, "00");

  // verify the the hex string length is even. This fixes issues with 10 base
  // hex values Example 70006900700000... (pip)
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
    file_entry.path = "[UNSUPPORTED SHELL EXTENSION]";
    return file_entry;
  }
  file_entry.path = name;
  return file_entry;
}

// returns property store name or GUID/id if name not found
std::string propertyStore(const std::string& shell_data,
                          const std::vector<size_t>& wps_list) {
  std::string guid_string;
  for (const auto& offsets : wps_list) {
    std::string guid_little = shell_data.substr(offsets + 8, 32);
    guid_string = guidParse(guid_little);
    // If GUID property set is found get the property set name
    for (const auto& property_list : kPropertySets) {
      if (guid_string != property_list) {
        continue;
      }
      std::string name_size = shell_data.substr(offsets + 48, 8);
      name_size = swapEndianess(name_size);
      int size = tryTo<int>(name_size, 16).takeOr(0);
      std::string string_hex = shell_data.substr(offsets + 74, (size + 1) * 4);
      boost::erase_all(string_hex, "00");
      std::string name;
      // Convert hex path to readable string
      try {
        name = boost::algorithm::unhex(string_hex);
      } catch (const boost::algorithm::hex_decode_error& /* e */) {
        LOG(WARNING)
            << "Failed to decode Windows Property List hex values to string: "
            << shell_data;
        return guid_string;
      }
      return name;
    }
  }
  return guid_string;
}

std::string networkShareItem(const std::string& shell_data) {
  for (const auto& net_id : kNetworkShareIds) {
    if (net_id == shell_data.substr(4, 2)) {
      // Network path ends with "00"
      std::string network_path =
          shell_data.substr(10, shell_data.find("00", 10) - 10);
      std::string name;
      try {
        name = boost::algorithm::unhex(network_path);
      } catch (const boost::algorithm::hex_decode_error& /* e */) {
        LOG(WARNING) << "Failed to decode ShellItem path hex values to string: "
                     << shell_data;
        return "[UNKNOWN NETWORK SHELL ITEM]";
      }
      return name;
    }
  }
  return "[UNKNOWN NETWORK SHELL ITEM]";
}

std::string zipContentItem(const std::string& shell_data) {
  std::string path_size_string = shell_data.substr(168, 4);
  path_size_string = swapEndianess(path_size_string);
  int path_size = tryTo<int>(path_size_string, 16).takeOr(0);

  std::string path = shell_data.substr(184, path_size * 4);
  // Path is in unicode, extra 00
  boost::erase_all(path, "00");

  try {
    path = boost::algorithm::unhex(path);
  } catch (const boost::algorithm::hex_decode_error& /* e */) {
    LOG(WARNING) << "Failed to decode ShellItem path hex values to string: "
                 << path;
    return "[ZIP PATH DECODE ERROR]";
  }
  // Zip folders can go down a max of two directories
  std::string second_path_size_string = shell_data.substr(176, 4);
  second_path_size_string = swapEndianess(second_path_size_string);
  int second_path_size = tryTo<int>(second_path_size_string, 16).takeOr(0);

  if (second_path_size != 0) {
    path += "/";
    std::string second_path =
        shell_data.substr((184 + (path_size * 4) + 4), second_path_size * 4);
    boost::erase_all(second_path, "00");

    try {
      second_path = boost::algorithm::unhex(second_path);
      path += second_path;
    } catch (const boost::algorithm::hex_decode_error& /* e */) {
      LOG(WARNING) << "Failed to decode ShellItem path hex values to string: "
                   << second_path;
      path += "[ZIP PATH DECODE ERROR]";
      return path;
    }
  }
  return path;
}

std::string rootFolderItem(const std::string& shell_data) {
  std::string guid_little = shell_data.substr(8, 32);
  std::string guid_string = guidParse(guid_little);
  return guid_string;
}

std::string driveLetterItem(const std::string& shell_data) {
  std::string volume;
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
  if (panel_id == "00") {
    return "All Control Panel Items";
  } else if (panel_id == "01") {
    return "Appearance and Personalization";
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

std::vector<std::string> ftpItem(const std::string& shell_data) {
  std::vector<std::string> ftp_data;
  std::string unicode = shell_data.substr(6, 2);
  std::string uri_size = shell_data.substr(8, 4);
  if (uri_size == "0000") {
    ftp_data.push_back("0000000000000000");
  } else {
    if (shell_data.size() < 92) {
      LOG(WARNING) << "Unexpected ShellItem URI size: " << shell_data;
      ftp_data.push_back("0000000000000000");
      ftp_data.push_back("[UNKNOWN NAME]");
      return ftp_data;
    }
    std::string access_time =
        shell_data.substr(28, 16); // shell data contains connection time
    ftp_data.push_back(access_time);
  }

  if (uri_size == "0000" && unicode == "80") {
    // find end of string
    size_t offset = shell_data.find("0000", 16);
    size_t hostname_size = offset - 12;
    std::string ftp_hostname = shell_data.substr(12, hostname_size);
    std::string name;
    boost::erase_all(ftp_hostname, "00");
    try {
      name = boost::algorithm::unhex(ftp_hostname);
    } catch (const boost::algorithm::hex_decode_error& /* e */) {
      LOG(WARNING)
          << "Failed to decode ShellItem URI/FTP hex values to string: "
          << shell_data;
      ftp_data.push_back("[UNKNOWN NAME]");
      return ftp_data;
    }
    ftp_data.push_back(name);
    return ftp_data;
  }

  if (shell_data.size() < 92) {
    LOG(WARNING) << "Unexpected ShellItem URI size: " << shell_data;
    ftp_data.push_back("[UNKNOWN NAME]");
    return ftp_data;
  }
  int hostname_size = 0;
  std::string name_size = shell_data.substr(84, 8);
  name_size = swapEndianess(name_size);
  // find end of string
  if (unicode == "80") {
    hostname_size = tryTo<int>(name_size, 16).takeOr(0) * 4;
  } else {
    hostname_size = tryTo<int>(name_size, 16).takeOr(0) * 2;
  }
  if (hostname_size == 0) {
    LOG(WARNING) << "Unexepcted hostname size: " << shell_data;
    ftp_data.push_back("[UNKNOWN NAME]");
    return ftp_data;
  }
  std::string ftp_hostname = shell_data.substr(92, hostname_size);
  std::string name;
  boost::erase_all(ftp_hostname, "00");

  try {
    name = boost::algorithm::unhex(ftp_hostname);
  } catch (const boost::algorithm::hex_decode_error& /* e */) {
    LOG(WARNING) << "Failed to decode ShellItem URI/FTP hex values to string: "
                 << shell_data;
    ftp_data.push_back("[UNKNOWN NAME]");
    return ftp_data;
  }
  ftp_data.push_back(name);
  return ftp_data;
}

std::string propertyViewDrive(const std::string& shell_data) {
  std::string drive_hex = shell_data.substr(26, 6);
  std::string name;
  try {
    name = boost::algorithm::unhex(drive_hex);
  } catch (const boost::algorithm::hex_decode_error& /* e */) {
    LOG(WARNING) << "Failed to decode ShellItem path hex values to string: "
                 << shell_data;
    return "[UNKNOWN USER PROPERTY DRIVE NAME]";
  }
  return name;
}

std::string variableFtp(const std::string& shell_data) {
  // Short FTP name starts at string offset 76
  if (shell_data.length() < 76) {
    LOG(WARNING) << "FTP Variable name smaller than 76 chars: " << shell_data;
    return "[UNKNOWN VARIABLE FTP NAME]";
  }
  std::string name_start = shell_data.substr(76);
  // Short name should end with 0000
  size_t offset = name_start.find("0000");

  if (offset == std::string::npos) {
    LOG(WARNING) << "Could not identify Variable FTP name: " << shell_data;
    return "[UNKNOWN VARIABLE FTP NAME]";
  }
  std::string long_name = name_start.substr(offset);
  boost::erase_all(long_name, "00");
  // Check to make sure name is even, fixes issues with 10 base characters
  // Ex: p is 70
  if (long_name.length() % 2 != 0) {
    long_name += "0";
  }
  std::string name;
  try {
    name = boost::algorithm::unhex(long_name);
  } catch (const boost::algorithm::hex_decode_error& /* e */) {
    LOG(WARNING) << "Failed to decode ShellItem path hex values to string: "
                 << shell_data;
    return "[UNKNOWN VARIABLE FTP NAME]";
  }
  return name;
}

std::string variableGuid(const std::string& shell_data) {
  std::string guid_little = shell_data.substr(28, 32);
  std::string guid_string = guidParse(guid_little);
  return guid_string;
}

std::string mtpFolder(const std::string& shell_data) {
  std::string name_size = shell_data.substr(124, 8);
  name_size = swapEndianess(name_size);
  int size = tryTo<int>(name_size, 16).takeOr(0);
  std::string path_name = shell_data.substr(148, size * 4);
  boost::erase_all(path_name, "00");
  std::string name;
  try {
    name = boost::algorithm::unhex(path_name);
  } catch (const boost::algorithm::hex_decode_error& /* e */) {
    LOG(WARNING) << "Failed to decode ShellItem path hex values to string: "
                 << shell_data;
    return "[UNKNOWN MTP FOLDER NAME]";
  }
  return name;
}

std::string mtpDevice(const std::string& shell_data) {
  std::string name_size = shell_data.substr(76, 8);
  name_size = swapEndianess(name_size);
  int size = tryTo<int>(name_size, 16).takeOr(0);
  std::string path_name = shell_data.substr(108, size * 4);
  boost::erase_all(path_name, "00");
  std::string name;
  try {
    name = boost::algorithm::unhex(path_name);
  } catch (const boost::algorithm::hex_decode_error& /* e */) {
    LOG(WARNING) << "Failed to decode ShellItem path hex values to string: "
                 << shell_data;
    return "[UNKNOWN MTP DEVICE NAME]";
  }
  return name;
}

std::string mtpRoot(const std::string& shell_data) {
  size_t name_end = shell_data.find("000000", 80);
  std::string path_name = shell_data.substr(80, name_end - 80);
  boost::erase_all(path_name, "00");
  std::string name;
  try {
    name = boost::algorithm::unhex(path_name);
  } catch (const boost::algorithm::hex_decode_error& /* e */) {
    LOG(WARNING) << "Failed to decode ShellItem path hex values to string: "
                 << shell_data;
    return "[UNKNOWN MTP ROOT NAME]";
  }
  return name;
}
} // namespace osquery