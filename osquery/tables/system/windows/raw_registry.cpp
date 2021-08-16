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
#include <osquery/core/windows/wmi.h>
#include <osquery/filesystem/fileops.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/windows/raw_registry.h>
#include <osquery/utils/windows/raw_registry.h>

#include <boost/filesystem.hpp>

#include <algorithm>
#include <string>

namespace osquery {
namespace tables {
// Gather all the main Windows Registry files
const std::string kHKLM = "Windows\\System32\\config\\";
const std::string kSystemRegistryFiles[5]{
    "SYSTEM", "SOFTWARE", "SECURITY", "SAM", "DEFAULT"};

// List of Regisry files allowed to be parsed, intial check to prevent osquery
// from reading multiple random files
const std::vector<std::string> kAllRegFiles{"userdiff",
                                            "BCM",
                                            "DRIVERS",
                                            "Amcache.hve",
                                            "COMPONENTS",
                                            "BBI",
                                            "ELAM",
                                            "BCD-Template",
                                            "SECURITY",
                                            "SAM",
                                            "SYSTEM",
                                            "SOFTWARE",
                                            "NTUSER.DAT",
                                            "UsrClass.dat"};
const std::string kUserRegistryFiles[2]{
    "NTUSER.DAT", "AppData\\Local\\Microsoft\\Windows\\UsrClass.dat"};

// Convert args to correct format (sleuthkit expects forward
// slashes and no drive letter)
void cleanRegPath(std::string& reg_path) {
  size_t path = reg_path.find(":", 0);
  if (path != std::string::npos) {
    reg_path = reg_path.substr(path + 2);
  }
  std::replace(reg_path.begin(), reg_path.end(), '\\', '/');
}

// Use WMI to get all the physical drives (taken from disk_info table)
std::vector<std::string> getDrives() {
  const WmiRequest wmiSystemReq("select * from Win32_DiskDrive");
  const std::vector<WmiResultItem>& wmiResults = wmiSystemReq.results();
  std::vector<std::string> drives;

  if (wmiResults.empty()) {
    LOG(WARNING) << "Error retrieving physical drives from WMI.";
    return drives;
  }
  for (const auto& wmi_data : wmiResults) {
    std::string drive_id;
    wmi_data.GetString("DeviceID", drive_id);
    drives.push_back(drive_id);
  }
  return drives;
}

std::vector<std::string> getDefaultRegFiles() {
  std::vector<std::string> reg_files;
  // Get system hives
  for (const auto& reg_file : kSystemRegistryFiles) {
    std::string reg_path = kHKLM + reg_file;
    reg_files.push_back(reg_path);
  }

  // Get user hives
  std::set<boost::filesystem::path> user_directories = getHomeDirectories();
  for (const auto& reg_file : user_directories) {
    std::string real_path = reg_file.string();

    if (real_path.find("%systemroot%", 0, 12) != std::string::npos &&
        real_path.find("ServiceProfiles", 13, 15) == std::string::npos) {
      continue;
    }
    for (const auto& file_reg : kUserRegistryFiles) {
      if (real_path.find("%systemroot%", 0, 12) != std::string::npos) {
        std::string windows_path = real_path.substr(12);
        real_path = "Windows" + windows_path;
      }
      std::string reg_path = real_path + "\\" + file_reg;
      reg_files.push_back(reg_path);
      // ServiceProfiles only have NTUSER.DAT
      if (real_path.find("Windows\\ServiceProfiles", 0) != std::string::npos) {
        break;
      }
    }
  }
  return reg_files;
}

void parseRegistryFiles(QueryData& results,
                        const std::string& reg_path,
                        const std::string& drive,
                        const std::string& original_file) {
  size_t file_start = original_file.rfind("\\");
  std::string filename = original_file.substr(file_start + 1);
  if (std::find(kAllRegFiles.begin(), kAllRegFiles.end(), filename) ==
      kAllRegFiles.end()) {
    return;
  }

  std::vector<RegTableData> reg_data = rawRegistry(reg_path, drive);

  for (const auto& reg_values : reg_data) {
    Row r;

    r["key"] = reg_values.key;
    r["path"] = reg_values.key_path;
    r["name"] = reg_values.key_name;
    r["type"] = reg_values.key_type;
    r["data"] = reg_values.key_data;
    r["modified_time"] = BIGINT(reg_values.modified_time);
    r["reg_path"] = original_file;
    r["physical_device"] = drive;
    r["reg_file"] = filename;
    results.push_back(r);
  }
}

void startRegParser(QueryData& results,
                    const std::vector<std::string>& physical_drives,
                    const std::vector<std::string>& reg_files) {
  for (const auto& drives : physical_drives) {
    for (const auto& files : reg_files) {
      std::string reg_path = files;
      cleanRegPath(reg_path);

      parseRegistryFiles(results, reg_path, drives, files);
    }
    // If we have results, we parsed the registry file, dont continue
    // looping through devices
    if (results.size() > 0) {
      break;
    }
  }
}

QueryData genRawRegistry(QueryContext& context) {
  QueryData results;
  auto paths = context.constraints["reg_path"].getAll(EQUALS);
  // Expand constraints
  context.expandConstraints(
      "reg_path",
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));
  auto devices = context.constraints["physical_device"].getAll(EQUALS);
  context.expandConstraints(
      "physical_device",
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));
  std::vector<std::string> query_regs = std::vector(paths.begin(), paths.end());
  std::vector<std::string> query_devices =
      std::vector(devices.begin(), devices.end());

  // Check for user specified registry file
  if (query_regs.empty()) {
    std::vector<std::string> reg_files;
    // Check for user specified device
    if (query_devices.empty()) {
      std::vector<std::string> physical_drives = getDrives();
      reg_files = getDefaultRegFiles();
      startRegParser(results, physical_drives, reg_files);
    } else {
      reg_files = getDefaultRegFiles();
      startRegParser(results, query_devices, reg_files);
    }
  } else {
    if (query_devices.empty()) {
      std::vector<std::string> physical_drives = getDrives();
      startRegParser(results, physical_drives, query_regs);
    } else {
      startRegParser(results, query_devices, query_regs);
    }
  }
  return results;
}
} // namespace tables
} // namespace osquery