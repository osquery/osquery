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
#include <osquery/logger/logger.h>
#include <osquery/tables/system/windows/registry.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/windows/shellitem.h>

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>

#include <string>
#include <cctype>
#include <vector>

#include <iostream>

const std::string kNetworkShareIds[6] = {"41", "42", "46", "47", "4C", "C3"};

const std::string kShellItemExtensions[23] = {
    "0400EFBE", "0000EFBE", "0100EFBE", "0200EFBE", "0300EFBE", "0500EFBE",
    "0600EFBE", "0800EFBE", "0900EFBE", "0A00EFBE", "0B00EFBE", "0C00EFBE",
    "0e00EFBE", "1000EFBE", "1300EFBE", "1400EFBE", "1600EFBE", "1700EFBE",
    "1900EFBE", "1A00EFBE", "2100EFBE", "2500EFBE", "2600EFBE"};

namespace osquery {
namespace tables {
constexpr auto kShellBagPath =
    "\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU";

std::string guidLookup(std::string& guid) {
  //std::cout << "GUID Lookup!" << std::endl;
  //std::cout << "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{" + guid + "}"
  //          << std::endl;
  QueryData guid_data;
  queryKey("HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{" + guid + "}", guid_data);
  for (const auto& rKey : guid_data) {
    auto key_type = rKey.find("type");
    auto key_path = rKey.find("path");
    if (key_type == rKey.end() || key_path == rKey.end()) {
      continue;
    }

    auto key_name = rKey.at("name");
    if (key_name == "(Default)") {
      //std::cout << rKey.at("data") << std::endl;
      if (rKey.at("data") == "") {
        return "{" + guid + "}";
      }
      return rKey.at("data");
    }
  }
  return "{" + guid + "}";
}

void parseShellData(const std::string shell_data,
    std::vector<std::string>& build_shellbag,
    QueryData& results) {
  std::string bag_entry = shell_data;

  // check shellitem extension version
  size_t offset;
  std::string extension_sig;
  size_t extension_offset = 0;
  for (const auto& ext : kShellItemExtensions) {
    offset = bag_entry.find(ext);
    if (offset != std::string::npos) {
      // std::cout << "Found a shellitem extension!. Sig is: " << ext
      //           << std::endl;
      extension_sig = bag_entry.substr(offset, 8);
      extension_offset = offset - 8;
      //std::cout << "Offset is: " << extension_offset << std::endl;
    }
  }
  if (extension_offset == 0) {
    std::cout << "ShellData: Could not find extension skipping for now..." << std::endl;
    return;
  }

  Row r;
  ShellFileEntryData file_entry = fileEntry(bag_entry, extension_offset);
  if (file_entry.version == 0) {
    std::string full_path = "";
    for (const auto& path : build_shellbag) {
      full_path += path;
    }
    full_path.pop_back();
    r["path"] = full_path;
    results.push_back(r);
    return;
  }

    // get modified time
  std::string fat_data = bag_entry.substr(16, 8);
  LONGLONG fat_timestamp = parseFatTime(fat_data);
  r["modified_time"] = INTEGER(fat_timestamp);

  // get created time
  fat_data = bag_entry.substr(extension_offset + 16, 8);
  fat_timestamp = parseFatTime(fat_data);
  r["created_time"] = INTEGER(fat_timestamp);

  // get access time
  fat_data = bag_entry.substr(extension_offset + 24, 8);
  fat_timestamp = parseFatTime(fat_data);
  r["accessed_time"] = INTEGER(fat_timestamp);

  if (file_entry.path != "") {
    build_shellbag.push_back(file_entry.path + "\\");
  }
  int mft_entry = file_entry.mft_entry;
  int mft_sequence = file_entry.mft_sequence;
  std::string full_path = "";
  for (const auto& path : build_shellbag) {
    full_path += path;
  }
 // std::cout << "FUll path is: " << full_path << std::endl;
  full_path.pop_back();

  r["path"] = full_path;
  r["first_interacted"] = INTEGER(0);
  r["last_interacted"] = INTEGER(0);
  r["mft_entry"] = INTEGER(mft_entry);
  r["mft_sequence"] = INTEGER(mft_sequence);
  results.push_back(r);
}

void parseShellEntries(const std::string& path,
                    std::vector<std::string>& build_shellbag,
                    QueryData& results) {
  QueryData shellbag_data;
  queryKey(path, shellbag_data);
  //std::cout << "Looping through shell data" << std::endl;
  for (const auto& rKey : shellbag_data) {
    auto key_type = rKey.find("type");
    auto key_path = rKey.find("path");
    if (key_type == rKey.end() || key_path == rKey.end()) {
      continue;
    }
    if (!isdigit(key_path->second.back())) {
      continue;
    }
    if (rKey.at("type") == "subkey") {
      continue;
    }
   // std::cout << key_path->second << std::endl;
   // std::cout << rKey.at("data") << std::endl;
    std::string bag_entry = rKey.at("data");
   
    //parseShellData(bag_entry, build_shellbag, results);
    
    // check shellitem extension version
    size_t offset;
    std::string extension_sig;
    size_t extension_offset = 0;
    for (const auto& ext : kShellItemExtensions) {
      offset = bag_entry.find(ext);
      if (offset != std::string::npos) {
       std::cout << "Found a shellitem extension!. Sig is: " << ext
                  << std::endl;
        extension_sig = bag_entry.substr(offset, 8);
        extension_offset = offset - 8;
        //std::cout << "Offset is: " << extension_offset << std::endl;
      }
    }
    Row r;
    if (extension_offset == 0) {
        // move network item to shellitem.cpp
      std::cout << "ShellEntries: Could not find extension skipping checking if network share"
                << std::endl;
      for (const auto& net_id : kNetworkShareIds) {
        std::cout << bag_entry.substr(4, 2) << std::endl;
        if (net_id == bag_entry.substr(4, 2)) {
          std::cout << net_id << std::endl;
          std::cout << "network id match!" << std::endl;
          // subtract 10 from the final offset from find
          std::string network_path =
              bag_entry.substr(10, bag_entry.find("00", 10)-10);
          std::cout << network_path << std::endl;
          std::string name;
          try {
            name = boost::algorithm::unhex(network_path);
          } catch (const boost::algorithm::hex_decode_error& /* e */) {
            LOG(WARNING)
                << "Failed to decode ShellItem path hex values to string: "
                << network_path;
            std::string full_path = "";
            for (const auto& path : build_shellbag) {
              full_path += path;
            }
            full_path.pop_back();
            full_path += "[UNKNOWN SHELL ITEM]";
            r["path"] = full_path;
            results.push_back(r);
            return;
          }
          build_shellbag.push_back(name+"\\");
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
        }
      }

      std::cout << "ShellEntries: Could not find extension skipping for now..." << std::endl;
      std::cout << bag_entry << std::endl;
      continue;
    }


    ShellFileEntryData file_entry = fileEntry(bag_entry, extension_offset);
    // if version is zero/unknown, just build current path and return
    if (file_entry.version == 0) {
      std::string full_path = "";
      for (const auto& path : build_shellbag) {
        full_path += path;
      }
      full_path.pop_back();
      r["path"] = full_path;
      results.push_back(r);
      return;
    }
    // get modified time
    std::string fat_data = bag_entry.substr(16, 8);
    LONGLONG fat_timestamp = parseFatTime(fat_data);
    r["modified_time"] = INTEGER(fat_timestamp);

    // get created time
    fat_data = bag_entry.substr(extension_offset + 16, 8);
    fat_timestamp = parseFatTime(fat_data);
    r["created_time"] = INTEGER(fat_timestamp);

    // get access time 
    fat_data = bag_entry.substr(extension_offset + 24, 8);
    fat_timestamp = parseFatTime(fat_data);
    r["accessed_time"] = INTEGER(fat_timestamp);


    if (file_entry.path != "") {
      build_shellbag.push_back(file_entry.path + "\\");
    }
    int mft_entry = file_entry.mft_entry;
    int mft_sequence = file_entry.mft_sequence;
    std::string full_path = "";
    for (const auto& path : build_shellbag) {
      std::cout << path << std::endl;
      full_path += path;
    }
    full_path.pop_back();

    r["path"] = full_path;
    r["first_interacted"] = INTEGER(0);
    r["last_interacted"] = INTEGER(0);
    r["mft_entry"] = INTEGER(mft_entry);
    r["mft_sequence"] = INTEGER(mft_sequence);
    results.push_back(r);
    parseShellEntries(key_path->second, build_shellbag, results);

    build_shellbag.pop_back();
  }
}

void parseShellbags(const std::string& path,
    std::vector<std::string>& build_shellbag,
    QueryData& results) {
  QueryData shellbag_data;
  queryKey(path, shellbag_data);
  for (const auto& rKey : shellbag_data) {
    auto key_type = rKey.find("type");
    auto key_path = rKey.find("path");
    if (key_type == rKey.end() || key_path == rKey.end()) {
      continue;
    }
    if (!isdigit(key_path->second.back())) {
      continue;
    }
    //std::cout << key_path->second << std::endl;
    if (rKey.at("data").find("19") == 0) {
      //std::cout << "Volume or Drive!" << std::endl;
      std::string volume;
      // Convert hex path to readable string
      try {
        volume = boost::algorithm::unhex(rKey.at("data").substr(6, 6));
      } catch (const boost::algorithm::hex_decode_error& /* e */) {
        LOG(WARNING) << "Failed to decode Shellbag hex values to string: "
                     << path;
        continue;
      }
      //std::cout << volume << std::endl;
      //std::cout << key_path->first << ":" << key_path->second << std::endl;
      build_shellbag.push_back(volume);
      parseShellEntries(key_path->second, build_shellbag, results);
      build_shellbag.pop_back();
    } else if( rKey.at("data") != "") {
      bool found_ext = false;

      for (const auto& ext : kShellItemExtensions) {
        if (rKey.at("data").find(ext) != std::string::npos) {
          std::cout << "Found a shellitem extension!. Sig is: " << ext
                     << std::endl;
          if (ext == "2600EFBE") {
            std::string guid_little = rKey.at("data").substr(8, 32);
            std::cout << "GUID little: " << guid_little << std::endl;
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
            std::string guid_string = guids[0] + "-" + guids[1] + "-" +
                                      guids[2] + "-" + guid_4 + "-" + guid_5;
            //std::cout << "CorrectGUID : " + guid_string << std::endl;
            std::string guid_name = guidLookup(guid_string);
            //std::cout << guid_name << std::endl;

            // this is a hack to make sure the guids are removed...
            if (build_shellbag.size() == 2) {
              build_shellbag.pop_back();
            }
            build_shellbag.push_back(guid_name + "\\");
            //if (guid_name != "") {
             // build_shellbag.push_back(guid_name + "\\");
            //}
            //continue;
            //found_ext = true;
          }
          found_ext = true;
        }
      }
      if (found_ext) {
        parseShellData(rKey.at("data"), build_shellbag, results);
        //continue;
      } else if(rKey.at("data").find("31535053") != std::string::npos) {
        std::cout << rKey.at("data") << std::endl;
        std::vector<size_t> wps_list;
        // check if Windows Property Store version 1SPS is in shellbag data
        size_t wps = rKey.at("data").find("31535053");
        while (wps != std::string::npos) {
          wps_list.push_back(wps);
          wps = rKey.at("data").find("31535053", wps+1);
        }
        std::string property_name = propertyStore(rKey.at("data"), wps_list);
        build_shellbag.push_back(property_name);
      } else {
        std::cout << "Unkonwn format?" << std::endl;
        build_shellbag.push_back("FIXME\\");
      }
      parseShellEntries(key_path->second, build_shellbag, results);
      build_shellbag.pop_back();
      //std::cout << "THIS PC: " << rKey.at("data") << std::endl;
    }
  }
 }

QueryData genShellbags(QueryContext& context) {
  QueryData results;
  QueryData users;

  queryKey("HKEY_USERS", users);
  for (const auto& rKey : users) {
    auto key_type = rKey.find("type");
    auto key_path = rKey.find("path");
    if (key_type == rKey.end() || key_path == rKey.end()) {
      continue;
    }
    std::string full_path = key_path->second + kShellBagPath;
    // Shellbags exist in SID_Classes Key/Hive
    if (full_path.find("_Classes") == std::string::npos) {
      continue;
    }
    //std::cout << full_path << std::endl;
    QueryData shellbag_results;
    queryKey(full_path, shellbag_results);
    for (const auto& uKey : shellbag_results) {
      auto key_type = uKey.find("type");
      auto key_path = uKey.find("path");
      if (key_type == uKey.end() || key_path == uKey.end()) {
        continue;
      }
      if (!isdigit(key_path->second.back())) {
        continue;
      }
      //std::cout << "Gettign keys!" << std::endl;
      //std::cout << key_path->second << std::endl;
      //std::cout << uKey.at("data") << std::endl;
      const size_t class_type = uKey.at("data").find("1F");
      if ( class_type == std::string::npos) {
        continue;
      }
      const std::string sort_index = uKey.at("data").substr(class_type + 2, 2);
      //std::cout << sort_index << std::endl;
      std::string guid_little = uKey.at("data").substr(8, 32);
      //std::cout << "GUID little: " << guid_little << std::endl;
      std::vector<std::string> guids;
      //std::string guid_1 = guid_little.substr(0, 8);
      guids.push_back(guid_little.substr(0, 8));
      guids.push_back(guid_little.substr(8, 4));
      guids.push_back(guid_little.substr(12, 4));

      //std::string guid_2 = guid_little.substr(8, 4);
      //std::string guid_3 = guid_little.substr(12, 4);
      std::string guid_4 = guid_little.substr(16, 4);
      std::string guid_5 = guid_little.substr(20, 12);
      for (auto& guid : guids) {
        std::reverse(guid.begin(), guid.end());
        for (std::size_t i = 0; i < guid.length(); i += 2) {
          std::swap(guid[i], guid[i + 1]);
        }
      }
      std::string guid_string = guids[0] + "-" + guids[1] + "-" + guids[2] +
                                "-" + guid_4 + "-" + guid_5;
      std::cout << "CorrectGUID : " + guid_string << std::endl;
      std::vector<std::string> build_shellbag;
      std::string guid_name = guidLookup(guid_string);
      std::cout << guid_name << std::endl;
      if (guid_name != "") {
        build_shellbag.push_back(guid_name + "\\");
      }
        parseShellbags(key_path->second, build_shellbag, results);
    }
  }
  return results;
}
} // namespace tables
} // namespace oquery