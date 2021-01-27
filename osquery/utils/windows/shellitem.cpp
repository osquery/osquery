/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/logger/logger.h>
#include <string>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/hex.hpp>

#include <iostream>

struct ShellFileEntryData {
  std::string path;
  long long dos_created;
  long long dos_accessed;
  int ext_size;
  int version;
  std::string extension_sig;
  std::string identifier;
  int mft_entry;
  int mft_sequence;
  int string_size;
};

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
ShellFileEntryData fileEntry(const std::string& shell_data, const size_t& entry_offset) {
  ShellFileEntryData file_entry;
  std::string version = shell_data.substr(entry_offset + 4, 4);
  //std::cout << "Parsing file entry!" << std::endl;
  // swap endianess
  std::reverse(version.begin(), version.end());
  for (std::size_t i = 0; i < version.length(); i += 2) {
    std::swap(version[i], version[i + 1]);
  }
  file_entry.version = std::stoi(version, nullptr, 16);
  if (file_entry.version < 7) {
    LOG(WARNING) << "Shellitem format unsupported. Expecting version 1 or version 7 or "
                    "higher, got version: "
                 << file_entry.version;
    file_entry.version = 0;
    return file_entry;
  }
  file_entry.extension_sig = shell_data.substr(entry_offset + 8, 8);
  //file_entry.dos_created = shell_data.substr(entry_offset + 16, 8);
  //file_entry.dos_accessed = shell_data.substr(entry_offset + 24, 8);
  file_entry.identifier = shell_data.substr(entry_offset + 32, 4);
  std::string mft_entry = shell_data.substr(entry_offset + 40, 12);
  // swap endianess
  std::reverse(mft_entry.begin(), mft_entry.end());
  for (std::size_t i = 0; i < mft_entry.length(); i += 2) {
    std::swap(mft_entry[i], mft_entry[i + 1]);
  }
  file_entry.mft_entry = std::stoi(mft_entry, nullptr, 16);

  std::string mft_sequence = shell_data.substr(entry_offset + 52, 4);
  std::reverse(mft_sequence.begin(), mft_sequence.end());
  for (std::size_t i = 0; i < mft_sequence.length(); i += 2) {
    std::swap(mft_sequence[i], mft_sequence[i + 1]);
  }
  file_entry.mft_sequence = std::stoi(mft_sequence, nullptr, 16);

    std::string string_size = shell_data.substr(entry_offset + 72, 4);
  std::reverse(string_size.begin(), string_size.end());
    for (std::size_t i = 0; i < string_size.length(); i += 2) {
    std::swap(string_size[i], string_size[i + 1]);
  }
    file_entry.string_size = std::stoi(string_size, nullptr, 16);
  std::string entry_name = shell_data.substr(entry_offset + 92);
   // std::cout << entry_name << std::endl;

    // path name ends with 0000
  size_t name_end = entry_name.find("0000");
    std::string shell_name = entry_name.substr(0, name_end);
  // Path is in unicode, extra 00
  boost::erase_all(shell_name, "00");

  // verify the the hex string length is even. This fixes issues with 10 base hex values
  // Example 7000690070000000... (pip)
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
  //std::cout << name << std::endl;
    file_entry.path = name;

  return file_entry;
}

// returns property store name or GUID/id if name not found
std::string propertyStore(
    const std::string& shell_data,
    const std::vector<size_t>& wps_list) {

  std::string guid_string;
  for (const auto& offsets : wps_list) {
     std::string guid_little = shell_data.substr(offsets + 8, 32);
    // std::cout << "GUID little: " << guid_little << std::endl;
    std::vector<std::string> guids;
    // std::string guid_1 = guid_little.substr(0, 8);
    guids.push_back(guid_little.substr(0, 8));
    guids.push_back(guid_little.substr(8, 4));
    guids.push_back(guid_little.substr(12, 4));

    // std::string guid_2 = guid_little.substr(8, 4);
    // std::string guid_3 = guid_little.substr(12, 4);
    std::string guid_4 = guid_little.substr(16, 4);
    std::string guid_5 = guid_little.substr(20, 12);
    for (auto& guid : guids) {
      std::reverse(guid.begin(), guid.end());
      for (std::size_t i = 0; i < guid.length(); i += 2) {
        std::swap(guid[i], guid[i + 1]);
      }
    }
    std::string guid_string = guids[0] + "-" + guids[1] + "-" + guids[2] + "-" +
                              guid_4 + "-" + guid_5;
    for (const auto& property_list : kPropertySets) {
      if (guid_string != property_list) {
        continue;
      }
      std::string name_size = shell_data.substr(offsets + 48, 8);
      //std::cout << name_size << std::endl;
      std::reverse(name_size.begin(), name_size.end());
      for (std::size_t i = 0; i < name_size.length(); i += 2) {
        std::swap(name_size[i], name_size[i + 1]);
      }
      unsigned int size = std::stoi(name_size, nullptr, 16);
      std::cout << size << std::endl;
      // String name size starts at 0 and its also in unicode
      //std::cout << shell_data.substr(offsets + 74, (size+1) * 4) << std::endl;
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
} // namespace osquery