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

#include <cctype>
#include <string>
#include <vector>

#include <iostream>

// Only 0400EFBE and 2600EFBE have been widely seen
const std::string kShellItemExtensions[23] = {
    "0400EFBE", "0000EFBE", "0100EFBE", "0200EFBE", "0300EFBE", "0500EFBE",
    "0600EFBE", "0800EFBE", "0900EFBE", "0A00EFBE", "0B00EFBE", "0C00EFBE",
    "0e00EFBE", "1000EFBE", "1300EFBE", "1400EFBE", "1600EFBE", "1700EFBE",
    "1900EFBE", "1A00EFBE", "2100EFBE", "2500EFBE", "2600EFBE"};

namespace osquery {
namespace tables {
constexpr auto kShellBagPath =
    "\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU";
constexpr auto kShellBagPathNtuser =
    "\\Software\\Microsoft\\Windows\\Shell\\BagMRU";

std::string guidLookup(std::string& guid) {
  QueryData guid_data;
  queryKey("HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{" + guid + "}",
           guid_data);
  for (const auto& rKey : guid_data) {
    auto key_type = rKey.find("type");
    auto key_path = rKey.find("path");
    if (key_type == rKey.end() || key_path == rKey.end()) {
      continue;
    }
    auto key_name = rKey.at("name");
    if (key_name == "(Default)") {
      if (rKey.at("data") == "") {
        return "{" + guid + "}";
      }
      return rKey.at("data");
    }
  }
  return "{" + guid + "}";
}

void parseShellData(const std::string& shell_data,
                    std::vector<std::string>& build_shellbag,
                    QueryData& results,
                    const std::string& sid) {
  Row r;
  r["sid"] = sid;
  size_t offset;
  std::string extension_sig = "";
  size_t extension_offset = 0;
  if (shell_data.find("0400EFBE") != std::string::npos) {
    offset = shell_data.find("0400EFBE");
    // std::cout << "Found a shellitem extension!. Sig is: " << "0400EFBE" <<
    // std::endl;
    extension_sig = shell_data.substr(offset, 8);
    extension_offset = offset - 8;
  } else if (shell_data.find("2600EFBE") != std::string::npos) {
    offset = shell_data.find("2600EFBE");
    // std::cout << "Found a shellitem extension!. Sig is: " << "2600EFBE" <<
    // std::endl;
    extension_sig = shell_data.substr(offset, 8);
    extension_offset = offset - 8;
  }
  // Check for BEEF sig, change to search for BEEF004 and BEEF0026
  /*
  for (const auto& ext : kShellItemExtensions) {
    offset = shell_data.find(ext);
    if (offset != std::string::npos) {
      std::cout << "Found a shellitem extension!. Sig is: " << ext << std::endl;
      extension_sig = shell_data.substr(offset, 8);
      extension_offset = offset - 8;

    }
  }*/

  // std::cout << shell_data << std::endl;
  std::string sig = shell_data.substr(4, 2);
  ShellFileEntryData file_entry;
  // YOU NEED TO ADD CHECKS FOR BEEF SIGS!!!!!!
  if (sig == "1F" && shell_data.find("4100750074006F004C00690073007400") ==
                         std::string::npos) { // Root Folder
    std::string root_name = rootFolderItem(shell_data);
    std::string guid_name = guidLookup(root_name);
    build_shellbag.push_back(guid_name + "\\");
    std::string full_path = "";
    for (const auto& path : build_shellbag) {
      full_path += path;
    }
    // std::cout << full_path << std::endl;
    full_path.pop_back();
    r["path"] = full_path;
    results.push_back(r);
    // No timestamps for root folder item
    return;
  } else if ((sig == "31" || sig == "30" || sig == "32" || sig == "35" ||
              sig == "B1") &&
             extension_sig == "0400EFBE") { // Directory/File Entry
    file_entry = fileEntry(shell_data);
  } else if (sig == "00" && extension_sig == "0400EFBE") { // Optical disc
    // Optical disc contains unique sig "AugM"
    if (shell_data.find("417567AD") == std::string::npos) {
      LOG(WARNING) << "Unknown ShellItem: " << shell_data;
      return;
    }

    return;
  } else if ((sig == "2F" || sig == "23" || sig == "25" || sig == "29" ||
              sig == "2A" || sig == "2E") &&
             extension_sig == "") { // add check for 19     // Drive Letter
    std::string drive_name = driveLetterItem(shell_data);
    build_shellbag.push_back(drive_name);
    std::string full_path = "";
    for (const auto& path : build_shellbag) {
      full_path += path;
    }
    // std::cout << full_path << std::endl;
    r["path"] = full_path;
    results.push_back(r);
    // No timestamps for drive letters
    return;
  } else if (sig == "01") { // Control Panel Category
    std::string panel = controlPanelCategoryItem(shell_data);
    build_shellbag.push_back(panel + "\\");
    std::string full_path = "";
    for (const auto& path : build_shellbag) {
      full_path += path;
    }
    full_path.pop_back();
    r["path"] = full_path;
    results.push_back(r);
    return;
  } else if (sig == "71") { // Control Panel
    std::string control_guid = controlPanelItem(shell_data);
    std::string guid_name = guidLookup(control_guid);

    build_shellbag.push_back(guid_name + "\\");
    std::string full_path = "";
    for (const auto& path : build_shellbag) {
      full_path += path;
    }
    full_path.pop_back();
    r["path"] = full_path;
    results.push_back(r);
    return;
  } else if (sig == "C3" || sig == "41" || sig == "42" || sig == "46" ||
             sig == "47" || sig == "4C") { // Network share
    std::string network_share = networkShareItem(shell_data);
    build_shellbag.push_back(network_share);
    std::string full_path = "";
    for (const auto& path : build_shellbag) {
      full_path += path;
    }
    // std::cout << full_path << std::endl;
    r["path"] = full_path;
    results.push_back(r);
    // No timestamps for network shares
    return;
  } else if (sig == "61") { // FTP/URI
    std::vector<std::string> ftp_data = ftpItem(shell_data);
    long long unix_time = littleEndianToUnixTime(ftp_data[0]);
    build_shellbag.push_back(ftp_data[1] + "\\");

    std::string full_path = "";
    for (const auto& path : build_shellbag) {
      full_path += path;
    }
    full_path.pop_back();
    r["path"] = full_path;
    r["accessed_time"] = unix_time;
    results.push_back(r);
    return;
  } else {
    if (extension_sig == "2600EFBE" && sig != "1F") {
      std::string guid_little = shell_data.substr(8, 32);
      std::string guid_string = guidParse(guid_little);
      std::string guid_name = guidLookup(guid_string);

      build_shellbag.push_back(guid_name + "\\");
      std::string full_path = "";
      for (const auto& path : build_shellbag) {
        full_path += path;
      }
      full_path.pop_back();
      r["path"] = full_path;
      results.push_back(r);
      return;
    } else if (shell_data.find("31535053") != std::string::npos) {
      // User Property List contains "Autolist", data is typically associated
      // with Explorer searches
      if (shell_data.find("4100750074006F004C00690073007400") !=
          std::string::npos) {
        build_shellbag.push_back("[USER PROPERTY VIEW]\\");
        std::string full_path = "";
        for (const auto& path : build_shellbag) {
          full_path += path;
        }
        // std::cout << full_path << std::endl;
        full_path.pop_back();
        r["path"] = full_path;
        results.push_back(r);
        return;
      }
      std::cout << "WPS" << std::endl;
      std::cout << extension_sig << std::endl;
      std::cout << shell_data << std::endl;
      std::vector<size_t> wps_list;
      // check if Windows Property Store version 1SPS is in shellbag data, there
      // could be multiple
      size_t wps = shell_data.find("31535053");
      while (wps != std::string::npos) {
        wps_list.push_back(wps);
        wps = shell_data.find("31535053", wps + 1);
      }
      std::string property_name = propertyStore(shell_data, wps_list);
      build_shellbag.push_back(property_name);
    } else if (extension_sig == "0400EFBE" &&
               sig != "1F") { // <----------- REmove this?
      file_entry = fileEntry(shell_data);
    } else {
      if (shell_data.length() > 200 && extension_sig == "") {
        std::cout << "ShellData: May be zip contents" << std::endl;
        std::cout << shell_data << std::endl;
        std::string path = zipContentItem(shell_data);
        build_shellbag.push_back(path + "\\");
        std::string full_path = "";
        for (const auto& path : build_shellbag) {
          full_path += path;
        }
        std::cout << full_path << std::endl;
        full_path.pop_back();
        r["path"] = full_path;
        results.push_back(r);
        return;
      }
      LOG(WARNING) << "Unsupported Shellbag format: " << shell_data;
      build_shellbag.push_back("[UNSUPPORTED FORMAT]\\");
      std::string full_path = "";
      for (const auto& path : build_shellbag) {
        full_path += path;
      }
      // std::cout << full_path << std::endl;
      full_path.pop_back();
      r["path"] = full_path;
      results.push_back(r);
      return;
    }
  }

  // std::cout << "Parsing out file entry data" << std::endl;
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

  r["modified_time"] = INTEGER(file_entry.dos_modified);
  r["created_time"] = INTEGER(file_entry.dos_created);
  r["accessed_time"] = INTEGER(file_entry.dos_accessed);

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

// Recursively loop through shellbag entries in the Registry
void parseShellbags(const std::string& path,
                    std::vector<std::string>& build_shellbag,
                    QueryData& results,
                    const std::string& sid) {
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
    if (rKey.at("data") == "") {
      continue;
    }
    // std::cout << rKey.at("data") << std::endl;
    parseShellData(rKey.at("data"), build_shellbag, results, sid);
    parseShellbags(key_path->second, build_shellbag, results, sid);
    if (build_shellbag.size() > 0) {
      build_shellbag.pop_back();
    }
  }
}

void parseRegistry(const std::string& full_path, const std::string& sid, QueryData& results) {
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

    if (uKey.at("data") == "") {
      continue;
    }
    std::vector<std::string> build_shellbag;
    parseShellData(uKey.at("data"), build_shellbag, results, sid);
    parseShellbags(key_path->second, build_shellbag, results, sid);
  }
}

QueryData genShellbags(QueryContext& context) {
  QueryData users;
  QueryData results;

  queryKey("HKEY_USERS", users);
  for (const auto& rKey : users) {
    auto key_type = rKey.find("type");
    auto key_path = rKey.find("path");
    if (key_type == rKey.end() || key_path == rKey.end()) {
      continue;
    }
    std::string full_path = key_path->second + kShellBagPath;
    size_t sid_start = full_path.find("S-");
    if (sid_start == std::string::npos) {
      continue;
    }
    size_t sid_end = full_path.find("_", sid_start);
    if (sid_end == std::string::npos) {
      sid_end = full_path.find("\\", sid_start);
    }
    std::string sid = full_path.substr(sid_start, sid_end-sid_start);
    // Shellbags may exist in both SID_Classes and SID Keys but the paths are different
    if (full_path.find("_Classes") == std::string::npos) {
      std::cout << full_path << std::endl;
      full_path = key_path->second + kShellBagPathNtuser;
      parseRegistry(full_path, sid, results);
      continue;
    }
    parseRegistry(full_path, sid, results);
  }
  return results;
}
} // namespace tables
} // namespace osquery