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
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/windows/windows_time.h>
#include <osquery/utils/windows/shellitem.h>

#include <string>
#include <vector>

namespace osquery {
namespace tables {
constexpr auto kShellBagPath =
    "\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU";
constexpr auto kShellBagPathNtuser =
    "\\Software\\Microsoft\\Windows\\Shell\\BagMRU";

std::string guidLookup(const std::string& guid) {
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
                    const std::string& sid,
                    const std::string& source) {
  Row r;
  r["sid"] = sid;
  r["source"] = source;
  std::string extension_sig = "";
  // "0400EFBE", "2600EFBE", "2500EFBE" are the primary shell extensions needed
  // to build directory paths
  if (shell_data.find("0400EFBE") != std::string::npos) {
    extension_sig = "0400EFBE";
  } else if (shell_data.find("2600EFBE") != std::string::npos) {
    extension_sig = "2600EFBE";
  } else if (shell_data.find("2500EFBE") != std::string::npos) {
    extension_sig = "2500EFBE";
  }

  std::string sig = shell_data.substr(4, 2);
  ShellFileEntryData file_entry;
  if (shell_data.length() > 200 && extension_sig == "" &&
      (shell_data.substr(80, 2) == "2F" ||
       shell_data.substr(76, 2) == "2F")) { // Zip contents
    std::string path = zipContentItem(shell_data);
    build_shellbag.push_back(path);
    std::string full_path = osquery::join(build_shellbag, "\\");
    r["path"] = full_path;
    results.push_back(r);
    return;
  } else if (sig == "1F" &&
             shell_data.find("31535053") == std::string::npos) { // Root Folder
    std::string name;
    std::string full_path;
    if (shell_data.substr(8, 2) == "2F") { // User Property View Drive
      name = propertyViewDrive(shell_data);
      // osquery::join adds "\" to entries, remove drive "\"
      name.pop_back();
      build_shellbag.push_back(name);
      full_path = osquery::join(build_shellbag, "\\");
      full_path += "\\";
    } else {
      std::string root_name = rootFolderItem(shell_data);
      name = guidLookup(root_name);
      build_shellbag.push_back(name);
      full_path = osquery::join(build_shellbag, "\\");
    }
    r["path"] = full_path;
    results.push_back(r);
    return;
  } else if ((sig == "31" || sig == "30" || sig == "32" || sig == "35" ||
              sig == "B1") &&
             extension_sig == "0400EFBE") { // Directory/File Entry
    file_entry = fileEntry(shell_data);
  } else if ((sig == "2F" || sig == "23" || sig == "25" || sig == "29" ||
              sig == "2A" || sig == "2E") &&
             (extension_sig == "" || extension_sig == "2600EFBE" ||
              extension_sig == "2500EFBE")) { // Drive Letter
    if (shell_data.substr(6, 2) == "80" &&
        (extension_sig == "2600EFBE" || extension_sig == "2500EFBE" ||
         extension_sig == "")) { // Check if GUID exists
      std::string guid_little = shell_data.substr(8, 32);
      std::string guid_string = guidParse(guid_little);
      std::string guid_name = guidLookup(guid_string);

      build_shellbag.push_back(guid_name);
      std::string full_path = osquery::join(build_shellbag, "\\");
      r["path"] = full_path;
      results.push_back(r);
      return;
    } else if (shell_data.find("5C007500730062002300") != std::string::npos &&
               extension_sig == "") { // Check for \usb#
      std::string name = mtpRoot(shell_data);
      build_shellbag.push_back(name);
      std::string full_path = osquery::join(build_shellbag, "\\");
      r["path"] = full_path;
      results.push_back(r);
      return;
    }

    // Drive letter should have ":\"
    if (shell_data.find("3A5C") == std::string::npos) {
      build_shellbag.push_back("[UNKNOWN DRIVE NAME]");
      std::string full_path = osquery::join(build_shellbag, "\\");
      r["path"] = full_path;
      results.push_back(r);
      return;
    }
    std::string drive_name = driveLetterItem(shell_data);
    // osquery::join adds "\" to entries, remove drive "\"
    drive_name.pop_back();
    build_shellbag.push_back(drive_name);
    std::string full_path = osquery::join(build_shellbag, "\\");

    r["path"] = full_path + "\\";
    results.push_back(r);
    return;
  } else if (sig == "01") { // Control Panel Category
    std::string panel = controlPanelCategoryItem(shell_data);
    build_shellbag.push_back(panel);
    std::string full_path = osquery::join(build_shellbag, "\\");
    r["path"] = full_path;
    results.push_back(r);
    return;
  } else if (sig == "71") { // Control Panel
    std::string control_guid = controlPanelItem(shell_data);
    std::string guid_name = guidLookup(control_guid);

    build_shellbag.push_back(guid_name);
    std::string full_path = osquery::join(build_shellbag, "\\");
    r["path"] = full_path;
    results.push_back(r);
    return;
  } else if (sig == "C3" || sig == "41" || sig == "42" || sig == "46" ||
             sig == "47" || sig == "4C") { // Network share
    std::string network_share = networkShareItem(shell_data);
    build_shellbag.push_back(network_share);
    std::string full_path = osquery::join(build_shellbag, "\\");
    r["path"] = full_path;
    results.push_back(r);
    return;
  } else if (sig == "61") { // FTP/URI
    std::vector<std::string> ftp_data = ftpItem(shell_data);
    long long unix_time = littleEndianToUnixTime(ftp_data[0]);
    build_shellbag.push_back(ftp_data[1]);
    std::string full_path = osquery::join(build_shellbag, "\\");
    r["path"] = full_path;
    r["accessed_time"] = BIGINT(unix_time);
    results.push_back(r);
    return;
  } else if (sig == "74" && shell_data.find("43465346") !=
                                std::string::npos) { // User File View
    file_entry = fileEntry(shell_data);
  } else if (sig == "00") { // Variable shell item, can contain a variety of
                            // shell item formats
    if (shell_data.find("EEBBFE23") != std::string::npos) {
      std::string guid_string = variableGuid(shell_data);
      std::string guid_name = guidLookup(guid_string);
      build_shellbag.push_back(guid_name);
      std::string full_path = osquery::join(build_shellbag, "\\");
      r["path"] = full_path;
      results.push_back(r);
      return;
    } else if (shell_data.substr(12, 8) == "05000000" ||
               shell_data.substr(12, 8) == "05000300") {
      std::string ftp_name = variableFtp(shell_data);
      build_shellbag.push_back(ftp_name);
      std::string full_path = osquery::join(build_shellbag, "\\");
      r["path"] = full_path;
      results.push_back(r);
      return;
    } else if (shell_data.find("31535053") != std::string::npos) {
      // User Property View contains several signatures, data is likely
      // associated with Explorer searches?
      if ((shell_data.find("D5DFA323") != std::string::npos) ||
          (shell_data.find("81191410") != std::string::npos) ||
          (shell_data.find("EEBBFE23") != std::string::npos) ||
          (shell_data.find("00EEBEBE") != std::string::npos)) {
        build_shellbag.push_back("[VARIABLE USER PROPERTY VIEW]");
        std::string full_path = osquery::join(build_shellbag, "\\");
        r["path"] = full_path;
        results.push_back(r);
        return;
      }
      std::vector<size_t> wps_list;
      // check if Windows Property Store version 1SPS is in shellbag data,
      // there could be multiple
      size_t wps = shell_data.find("31535053");
      while (wps != std::string::npos) {
        wps_list.push_back(wps);
        wps = shell_data.find("31535053", wps + 1);
      }
      std::string property_name = propertyStore(shell_data, wps_list);
      build_shellbag.push_back(property_name);
      std::string full_path = osquery::join(build_shellbag, "\\");
      r["path"] = full_path;
      results.push_back(r);
      return;
    } else if (shell_data.find("0505203110") !=
               std::string::npos) { // MTP Device
      std::string name = mtpDevice(shell_data);
      build_shellbag.push_back(name);
      std::string full_path = osquery::join(build_shellbag, "\\");
      r["path"] = full_path;
      results.push_back(r);
      return;
    } else if (shell_data.find("06201907") != std::string::npos) { // MTP Folder
      std::string name = mtpFolder(shell_data);
      build_shellbag.push_back(name);
      std::string full_path = osquery::join(build_shellbag, "\\");
      r["path"] = full_path;
      results.push_back(r);
      return;
    }
    LOG(WARNING) << "Unknown variable format: " << shell_data;
    build_shellbag.push_back("[UNKNOWN VARIABLE FORMAT]");
    std::string full_path = osquery::join(build_shellbag, "\\");
    r["path"] = full_path;
    results.push_back(r);
    return;
  } else {
    if (shell_data.find("31535053") != std::string::npos) {
      if (shell_data.find("D5DFA323") !=
          std::string::npos) { // User Property View
        std::string property_guid = shell_data.substr(226, 32);
        std::string guid_string = guidParse(property_guid);

        std::string guid_name = guidLookup(guid_string);
        build_shellbag.push_back(guid_name);
        std::string full_path = osquery::join(build_shellbag, "\\");
        r["path"] = full_path;
        results.push_back(r);
        return;
      }
      // User Property View may have additional other types of signatures, data
      // is likely associated with Explorer searches?
      if ((shell_data.find("81191410") != std::string::npos) ||
          (shell_data.find("EEBBFE23") != std::string::npos) ||
          (shell_data.find("BBAF933B") != std::string::npos) ||
          (shell_data.find("00EEBEBE") != std::string::npos)) {
        build_shellbag.push_back("[USER PROPERTY VIEW]");
        std::string full_path = osquery::join(build_shellbag, "\\");
        r["path"] = full_path;
        results.push_back(r);
        return;
      }
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
      std::string full_path = osquery::join(build_shellbag, "\\");
      r["path"] = full_path;
      results.push_back(r);
      return;
    } else {
      LOG(WARNING) << "Unsupported Shellbag format: " << shell_data;
      build_shellbag.push_back("[UNSUPPORTED FORMAT]");
      std::string full_path = osquery::join(build_shellbag, "\\");
      r["path"] = full_path;
      results.push_back(r);
      return;
    }
  }

  if (file_entry.path == "[UNSUPPORTED SHELL EXTENSION]") {
    build_shellbag.push_back(file_entry.path);
    std::string full_path = osquery::join(build_shellbag, "\\");
    r["path"] = full_path;
    results.push_back(r);
    return;
  }

  r["modified_time"] = BIGINT(file_entry.dos_modified);
  r["created_time"] = BIGINT(file_entry.dos_created);
  r["accessed_time"] = BIGINT(file_entry.dos_accessed);

  build_shellbag.push_back(file_entry.path);
  long long mft_entry = file_entry.mft_entry;
  int mft_sequence = file_entry.mft_sequence;
  std::string full_path = osquery::join(build_shellbag, "\\");

  r["path"] = full_path;
  r["mft_entry"] = BIGINT(mft_entry);
  r["mft_sequence"] = INTEGER(mft_sequence);
  results.push_back(r);
}

// Recursively loop through shellbag entries in the Registry
void parseShellbags(const std::string& path,
                    std::vector<std::string>& build_shellbag,
                    QueryData& results,
                    const std::string& sid,
                    const std::string& source) {
  QueryData shellbag_data;
  queryKey(path, shellbag_data);
  for (const auto& rKey : shellbag_data) {
    auto key_type = rKey.find("type");
    auto key_path = rKey.find("path");
    if (key_type == rKey.end() || key_path == rKey.end()) {
      continue;
    }
    // For Shellbags Reg keys the last character is a number
    if (!isdigit(key_path->second.back())) {
      continue;
    }
    if (rKey.at("data") == "") {
      continue;
    }
    parseShellData(rKey.at("data"), build_shellbag, results, sid, source);
    parseShellbags(key_path->second, build_shellbag, results, sid, source);
    if (build_shellbag.size() > 0) {
      build_shellbag.pop_back();
    }
  }
}

void parseRegistry(const std::string& full_path,
                   const std::string& sid,
                   QueryData& results,
                   const std::string& source) {
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
    parseShellData(uKey.at("data"), build_shellbag, results, sid, source);
    parseShellbags(key_path->second, build_shellbag, results, sid, source);
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
    std::string sid = full_path.substr(sid_start, sid_end - sid_start);
    // Shellbags may exist in both SID_Classes (UsrClass.dat) and SID
    // (NTUSER.dat) Keys but the paths are different
    if (full_path.find("_Classes") == std::string::npos) {
      full_path = key_path->second + kShellBagPathNtuser;
      std::string source = "ntuser.dat";
      parseRegistry(full_path, sid, results, source);
      continue;
    }
    std::string source = "usrclass.dat";
    parseRegistry(full_path, sid, results, source);
  }
  return results;
}
} // namespace tables
} // namespace osquery