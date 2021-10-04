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
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/windows/raw_registry.h>

#include <string>
#include <vector>

namespace osquery {
namespace tables {

void parseAmcacheExecution(QueryData& results,
                           const std::vector<RegTableData>& amcache_data,
                           const std::string& source_path,
                           const std::string& physical_device) {
  // Loop through the registry entries until we reach
  // {GUID}\Root\InventoryApplicationFile Windows 10 1709 and higher the data is
  // in InventoryApplicationFile
  for (int amcache_results = 0; amcache_results < amcache_data.size();
       amcache_results++) {
    if (amcache_data[amcache_results].key.find("Root\\InventoryApplicationFile",
                                               39) != std::string::npos) {
      std::string key = amcache_data[amcache_results].key;
      if (key.find("|") != std::string::npos) {
        Row r;
        int i = amcache_results;
        r["first_run_time"] = BIGINT(amcache_data[i].modified_time);
        r["source"] = source_path;
        r["physical_device"] = physical_device;

        // Get all the registry key data values associated with the registry key
        while (i < amcache_data.size()) {
          if (amcache_data[i].key != key) {
            break;
          }
          // Not all values exist for every amcache entry
          if (amcache_data[i].key_name == "LowerCaseLongPath") {
            r["path"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "BinFileVersion") {
            r["bin_file_version"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "AppxPackageFullName") {
            r["appx_package_fullname"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "AppxPackageRelativeId") {
            r["appx_package_relative_id"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "BinaryType") {
            r["binary_type"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "FileId") {
            // SHA1 hash starts with 4 zeros, check and discard them
            if (amcache_data[i].key_data.find("0000", 0, 4) !=
                std::string::npos) {
              r["sha1"] = amcache_data[i].key_data.substr(4);
            } else {
              r["sha1"] = amcache_data[i].key_data;
            }
          } else if (amcache_data[i].key_name == "IsOsComponent") {
            r["is_os_component"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "IsPeFile") {
            r["is_pe_file"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "Language") {
            r["language"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "LinkDate") {
            r["link_date"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "Name") {
            r["filename"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "OriginalFileName") {
            r["original_filename"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "LongPathHash") {
            r["long_path_hash"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "ProductName") {
            r["product_name"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "ProductVersion") {
            r["product_version"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "ProgramId") {
            r["program_id"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "Publisher") {
            r["publisher"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "Size") {
            r["size"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "Usn") {
            r["usn"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "Version") {
            r["version"] = amcache_data[i].key_data;
          }
          i++;
        }
        results.push_back(r);
        // Forward loop to next registry key
        amcache_results = i - 1;
      }
    } // Also check old Registry key data
      // {GUID}\Root\File\{GUID}
    else if (amcache_data[amcache_results].key.find("Root\\File", 39) !=
             std::string::npos) {
      // Skip the GUID subkey
      amcache_results++;
      std::string key = amcache_data[amcache_results].key;
      // 0000 is the key name separator, similar to "|" above
      if (key.find("0000") != std::string::npos) {
        Row r;
        int i = amcache_results;
        r["first_run_time"] = BIGINT(amcache_data[i].modified_time);
        r["source"] = source_path;
        r["physical_device"] = physical_device;
        // Get all the registry key data values associated with the registry key
        while (i < amcache_data.size()) {
          if (amcache_data[i].key != key) {
            break;
          }
          // Not all values exist for every amcache entry, and the values are in
          // hex string
          if (amcache_data[i].key_name == "0") {
            r["product_name"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "1") {
            r["publisher"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "2") {
            r["product_version"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "3") {
            r["language"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "5") {
            r["bin_file_version"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "6") {
            r["size"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "f") {
            r["link_date"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "15") {
            r["path"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "1") {
            r["program_id"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "100") {
            r["publisher"] = amcache_data[i].key_data;
          } else if (amcache_data[i].key_name == "101") {
            // SHA1 hash starts with 4 zeros, check and discard them
            if (amcache_data[i].key_data.find("0000", 0, 4) !=
                std::string::npos) {
              r["sha1"] = amcache_data[i].key_data.substr(4);
            } else {
              r["sha1"] = amcache_data[i].key_data;
            }
          }
          i++;
        }
        results.push_back(r);
        // Forward loop to next registry key
        amcache_results = i - 1;
      }
    }
  }
}

QueryData genAmcache(QueryContext& context) {
  QueryData results;
  auto device = context.constraints["physical_device"].getAll(EQUALS);

  std::string physical_device = "\\\\.\\PhysicalDrive0";
  if (!device.empty()) {
    auto value = std::next(device.begin(), 0);
    physical_device = *value;
  }
  std::string reg_path = "Windows/appcompat/Programs/Amcache.hve";

  auto source = context.constraints["source"].getAll(EQUALS);
  if (!source.empty()) {
    auto value = std::next(source.begin(), 0);
    reg_path = *value;
    std::string original_path = reg_path;
    cleanRegPath(reg_path);
    std::vector<RegTableData> amcache_data =
        rawRegistry(reg_path, physical_device);
    parseAmcacheExecution(
        results, amcache_data, original_path, physical_device);
    return results;
  }
  std::vector<RegTableData> amcache_data =
      rawRegistry(reg_path, physical_device);
  parseAmcacheExecution(results, amcache_data, reg_path, physical_device);
  return results;
}
} // namespace tables
} // namespace osquery