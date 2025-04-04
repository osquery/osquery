/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <regex>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>

#include "osquery/tables/system/windows/registry.h"

namespace osquery {
namespace tables {

// Function to reverse a string
std::string reverseString(const std::string& input) {
  std::string reversed = input;
  std::reverse(reversed.begin(), reversed.end());
  return reversed;
}

// Function to convert a registry-encoded GUID into a standard GUID
std::string decodeMsiRegistryGuid(const std::string& encoded) {
  // Ensure the encoded string is exactly 32 characters long
  if (encoded.length() != 32) {
    VLOG(1) << "Invalid registry GUID '" << encoded << "'";
    return "";
  }

  // Microsoft uses a custom encoding for GUIDs in the registry
  // It reverses the order of the bytes in the string
  // This 2CCAB6107DB47314AB175756630CCD04
  // 1.  Reverse last 2 characters 04
  // 2.  Reverse next 2 characters CD
  // 3.  Reverse next 2 characters 0C
  // 4.  Reverse next 2 characters 63
  // 5.  Reverse next 2 characters 56
  // 6.  Reverse next 2 characters 57
  // 7.  Reverse next 2 characters 17
  // 8.  Reverse next 2 characters AB
  // 9.  Reverse next 4 characters 7314
  // 10. Reverse next 4 characters 7DB4
  // 11. Reverse first 8 characters 2CCAB610
  // becomes 016BACC2-4BD7-4137-BA71-756536C0DC40

  std::string str = reverseString(encoded.substr(0, 8)) + "-" +
                    reverseString(encoded.substr(8, 4)) + "-" +
                    reverseString(encoded.substr(12, 4)) + "-" +
                    reverseString(encoded.substr(16, 2)) +
                    reverseString(encoded.substr(18, 2)) + "-" +
                    reverseString(encoded.substr(20, 2)) +
                    reverseString(encoded.substr(22, 2)) +
                    reverseString(encoded.substr(24, 2)) +
                    reverseString(encoded.substr(26, 2)) +
                    reverseString(encoded.substr(28, 2)) +
                    reverseString(encoded.substr(30, 2));

  return "{" + str + "}";
}

// Function to return a map of product code -> upgrade code
// Note that this is not a 1:1 mapping, a single upgrade code can have many
// product codes However, a product code can only have one upgrade code
std::map<std::string, std::string> generateProductCodeUpgradeCodeMap() {
  std::map<std::string, std::string> productCodeUpgradeCodeMap;
  std::set<std::string> upgradeCodeKeys = {
      "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Installer\\UpgradeCodes",
      "HKEY_LOCAL_"
      "MACHINE\\SOFTWARE\\WOW6432Node\\Classes\\Installer\\UpgradeCodes",
  };

  for (const auto& key : upgradeCodeKeys) {
    QueryData regResults;
    queryKey(key, regResults);
    for (const auto& rKey : regResults) {
      // Each subkey represents an upgrade code
      if (rKey.at("type") != "subkey") {
        continue;
      }

      auto upgradeCode = decodeMsiRegistryGuid(rKey.at("name"));
      if (upgradeCode.empty()) {
        continue;
      }

      // Each upgrade code can have 1 or more product codes
      QueryData upgradeCodeResults;
      queryKey(rKey.at("path"), upgradeCodeResults);
      for (const auto& pKey : upgradeCodeResults) {
        // name contains the data for the product code
        const auto& encryptedProductCode = pKey.find("name");
        if (encryptedProductCode != pKey.end()) {
          auto productCode =
              decodeMsiRegistryGuid(encryptedProductCode->second);
          if (productCode.empty()) {
            continue;
          }
          std::transform(productCode.begin(),
                         productCode.end(),
                         productCode.begin(),
                         ::toupper);
          productCodeUpgradeCodeMap[productCode] = upgradeCode;
        }
      }
    }
  }

  return productCodeUpgradeCodeMap;
}

void keyEnumPrograms(const std::string& key,
                     std::set<std::string>& processed,
                     std::map<std::string, std::string> upgradeCodeMap,
                     QueryData& results) {
  QueryData regResults;
  queryKey(key, regResults);
  for (const auto& rKey : regResults) {
    // Each subkey represents a program, skip if not a subkey
    if (rKey.at("type") != "subkey") {
      continue;
    }

    // Ensure we only process each program one time
    const auto& fullProgramName = rKey.at("path");
    if (processed.find(fullProgramName) != processed.end()) {
      continue;
    }
    processed.insert(fullProgramName);

    // Query additional information about the program
    QueryData appResults;
    queryKey(fullProgramName, appResults);
    Row r;

    // Attempt to derive the program identifying GUID
    std::string identifyingNumber;
    std::smatch matches;
    std::regex expression(
        "(\\{[a-fA-F0-9]+-[a-fA-F0-9]+-[a-fA-F0-9]+-[a-fA-F0-9]+-[a-fA-F0-9]+"
        "\\})$");
    if (std::regex_search(fullProgramName, matches, expression)) {
      identifyingNumber = matches[0];
      r["identifying_number"] = identifyingNumber;
    }

    if (!identifyingNumber.empty()) {
      std::string identifyingNumberUpper = identifyingNumber;
      std::transform(identifyingNumberUpper.begin(),
                     identifyingNumberUpper.end(),
                     identifyingNumberUpper.begin(),
                     ::toupper);

      const auto& upgradeCode = upgradeCodeMap[identifyingNumberUpper];
      if (!upgradeCode.empty()) {
        r["upgrade_code"] = upgradeCode;
      }
    }

    for (const auto& aKey : appResults) {
      auto name = aKey.find("name");
      if (identifyingNumber.empty() && name->second == "BundleIdentifier") {
        r["identifying_number"] = aKey.at("data");
      }
      if (name->second == "DisplayName") {
        r["name"] = aKey.at("data");
      }
      if (name->second == "DisplayVersion") {
        r["version"] = aKey.at("data");
      }
      if (name->second == "InstallLocation") {
        r["install_location"] = aKey.at("data");
      }
      if (name->second == "InstallSource") {
        r["install_source"] = aKey.at("data");
      }
      if (name->second == "Language") {
        r["language"] = aKey.at("data");
      }
      if (name->second == "Publisher") {
        r["publisher"] = aKey.at("data");
      }
      if (name->second == "UninstallString") {
        r["uninstall_string"] = aKey.at("data");
      }
      if (name->second == "InstallDate") {
        r["install_date"] = aKey.at("data");
      }
    }
    if (!r.empty()) {
      results.push_back(r);
    }
  }
}

QueryData genPrograms(QueryContext& context) {
  QueryData results;

  std::set<std::string> programKeys = {
      "HKEY_LOCAL_"
      "MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
      "HKEY_LOCAL_"
      "MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Unin"
      "stall",
  };

  std::set<std::string> userProgramKeys;
  expandRegistryGlobs(
      "HKEY_USERS\\%\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
      userProgramKeys);
  programKeys.insert(userProgramKeys.begin(), userProgramKeys.end());

  const auto& upgradeCodeMap = generateProductCodeUpgradeCodeMap();
  std::set<std::string> processedPrograms;
  for (const auto& k : programKeys) {
    keyEnumPrograms(k, processedPrograms, upgradeCodeMap, results);
  }

  return results;
}
} // namespace tables
} // namespace osquery
