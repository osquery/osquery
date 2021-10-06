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
#include <osquery/filesystem/fileops.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
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
                    const std::string& physical_drive,
                    const std::vector<std::string>& reg_files) {
  for (const auto& files : reg_files) {
    std::string reg_path = files;
    cleanRegPath(reg_path);

    parseRegistryFiles(results, reg_path, physical_drive, files);
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
  auto device = context.constraints["physical_device"].getAll(EQUALS);

  std::vector<std::string> query_regs = std::vector(paths.begin(), paths.end());
  std::string physical_drive = "\\\\.\\PhysicalDrive0";

  // Check for user specified registry file
  if (query_regs.empty()) {
    std::vector<std::string> reg_files;
    // Check for user specified device
    if (device.empty()) {
      reg_files = getDefaultRegFiles();
      startRegParser(results, physical_drive, reg_files);
    } else {
      reg_files = getDefaultRegFiles();
      auto value = std::next(device.begin(), 0);
      physical_drive = *value;
      startRegParser(results, physical_drive, reg_files);
    }
  } else {
    if (device.empty()) {
      startRegParser(results, physical_drive, query_regs);
    } else {
      auto value = std::next(device.begin(), 0);
      physical_drive = *value;
      startRegParser(results, physical_drive, query_regs);
    }
  }
  return results;
}
} // namespace tables
} // namespace osquery