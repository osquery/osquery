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

// Function to extract attributes from a tag
std::map<std::string, std::string> parseAttributes(
    const std::string& tagContent) {
  std::regex attributeRegex("((\\w+)=\"([^\"]*)\")");
  std::smatch match;
  std::map<std::string, std::string> attributes;

  std::string::const_iterator searchStart(tagContent.cbegin());
  while (std::regex_search(
      searchStart, tagContent.cend(), match, attributeRegex)) {
    // match[1] is the entire attribute="value" string
    // match[2] is the attribute name
    // match[3] is the attribute value
    attributes[match[2]] = match[3];
    searchStart = match.suffix().first;
  }

  return attributes;
}

// Function to extract the contents of a specific tag
std::string getTagContent(const std::string& xml, const std::string& tagName) {
  std::regex tagRegex("<" + tagName + "[\\s\\S]*?>([\\s\\S]*?)<\\/" + tagName +
                      ">");
  std::smatch match;

  if (std::regex_search(xml, match, tagRegex)) {
    // match[0] is the entire tag with contents <TagName>contents</TagName>
    // match[1] is the contents of the tag
    return match[1];
  }
  return "";
}

// Function to find self closing tag in xml
std::string findSelfClosingTag(const std::string& xml,
                               const std::string& tagName) {
  std::regex tagRegex("<" + tagName + "[\\s\\S]*?/>");
  std::smatch match;

  if (std::regex_search(xml, match, tagRegex)) {
    // match[0] is the entire self-closing tag
    return match[0];
  }
  return "";
}

// Convert a Unix timestamp to a date in YYYYMMDD format
std::string formatTimestampToDate(time_t timestamp) {
  try {
    // Convert the timestamp to a tm structure
    std::tm* timeInfo = std::gmtime(&timestamp);

    // Format the date as YYYYMMDD
    std::ostringstream oss;
    oss << std::put_time(timeInfo, "%Y%m%d");
    return oss.str();
  } catch (...) {
    return "";
  }
}

std::string packageFamilyNameFromPackageFullName(
    const std::string& packageFullName) {
  // The package full name format
  // <PackageName>_<Version>_<Architecture>__<PublisherHash>
  // Example:
  // MSTeams_25060.205.3499.6849_arm64__8wekyb3d8bbwe
  // The package family name
  // [PackageName + "_" + PublisherHash]
  // shall become the identifying number/"bundle identifier"

  auto pos = packageFullName.find('_');
  std::string packageName;
  if (pos != std::string::npos) {
    packageName = packageFullName.substr(0, pos);
  }

  pos = packageFullName.find("__");
  std::string publisherHash;
  if (pos != std::string::npos) {
    publisherHash = packageFullName.substr(pos + 2);
  }

  if (publisherHash.empty()) {
    // This package is an inbox or framework package, often times a part of core
    // windows PRI-based naming format:
    // <PackageName>_<Version>_<Architecture>_<ResourceQualifer>_<PublisherHash>
    // Example: Windows.PrintDialog_6.2.3.0_neutral_neutral_cw5n1h2txyewy
    pos = packageFullName.find_last_of('_');
    if (pos != std::string::npos) {
      publisherHash = packageFullName.substr(pos + 1);
    }
  }

  if (packageName.empty() || publisherHash.empty()) {
    // Some kind of unknown package
    LOG(INFO) << "Non MSIX or PRI/resource package detected:'" +
                     packageFullName + "'";
    return "";
  }

  return packageName + "_" + publisherHash;
}

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

void genMsixPrograms(const std::string& key,
                     std::set<std::string>& packageFamilyNameProcessed,
                     QueryData& results) {
  QueryData regResults;
  queryKey(key, regResults);
  for (const auto& rKey : regResults) {
    // Each subkey represents a package, skip if not a subkey
    if (rKey.at("type") != "subkey") {
      continue;
    }
    const auto& regPath = rKey.at("path");
    const auto& regPackageFullName = rKey.at("name");

    // Get all registry entries for the package
    QueryData appResults;
    queryKey(regPath, appResults);
    Row result;

    result["identifying_name"] = regPackageFullName;
    result["package_family_name"] =
        packageFamilyNameFromPackageFullName(regPackageFullName);

    for (const auto& aKey : appResults) {
      auto name = aKey.find("name");

      if (name->second == "PackageRootFolder") {
        result["install_location"] = aKey.at("data");
        std::string filePath =
            result["install_location"] + "\\AppxManifest.xml";

        // btime "Birth Time"
        // When a file is first created, btime is set and does not change
        // ::Warning:: not all filesystems support btime
        // Older file systems such as ext3 or FAT32 will have this missing
        WINDOWS_STAT file_stat;
        auto rtn = platformStat(filePath.c_str(), &file_stat);
        if (rtn.ok()) {
          result["install_date"] = formatTimestampToDate(file_stat.btime);
        }

        auto s = osquery::pathExists(filePath);
        if (!s.ok()) {
          // Skip this package, as we cannot find the manifest file
          // We can extract some information from the registry key
          // <PackageName>_<Version>_<Architecture>__<PublisherHash>
          // Example:
          // MSTeams_25060.205.3499.6849_arm64__8wekyb3d8bbwe
          // But all proper MSIX packages have an AppxManifest.xml file
          VLOG(1) << "Cannot find manifest file:'" + filePath + "'";
          result.clear();
          continue;
        }

        std::string xmlContent;
        s = osquery::readFile(filePath, xmlContent);
        if (!s.ok()) {
          // Skip this package, as we cannot read the manifest file
          VLOG(1) << "Cannot read manifest file:'" + filePath + "'";
          result.clear();
          continue;
        }

        // Find the Identity tag, extract attributes
        std::string identityTag = findSelfClosingTag(xmlContent, "Identity");
        if (!identityTag.empty()) {
          auto attributes = parseAttributes(identityTag);
          result["name"] = attributes["Name"];
          result["publisher"] = attributes["Publisher"];
          result["version"] = attributes["Version"];
        }

        // Find the Properties tag, extract child tags
        std::string propertiesTag = getTagContent(xmlContent, "Properties");
        if (!propertiesTag.empty()) {
          auto displayName = getTagContent(propertiesTag, "DisplayName");
          auto publisherDisplayName =
              getTagContent(propertiesTag, "PublisherDisplayName");

          // "ms-resource:" prefix means that the string is dynamically
          // generated from a .pri file .pri file is a binary index of all
          // localized and scaled resources compiled from .resw files or
          // .resources at build time
          if (!displayName.empty() &&
              displayName.find("ms-resource") == std::string::npos) {
            result["name"] = displayName;
          }
          if (!publisherDisplayName.empty() &&
              publisherDisplayName.find("ms-resource") == std::string::npos) {
            result["publisher"] = publisherDisplayName;
          }
        }

        // Done processing this package registry entries
        // No need to read anymore keys
        continue;
      }
    } // end processing package registry entry

    if (!result.empty()) {
      auto packageKey = result["package_family_name"];
      if (packageKey.empty()) {
        // This should never happen
        packageKey = result["name"];
      }

      if (packageFamilyNameProcessed.find(packageKey) ==
          packageFamilyNameProcessed.end()) {
        packageFamilyNameProcessed.insert(packageKey);
        results.push_back(result);
      }
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

  std::set<std::string> userMsixKeys;
  expandRegistryGlobs(
      "HKEY_USERS\\%\\Software\\Classes\\Local "
      "Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Reposi"
      "tory\\Packages",
      userMsixKeys);

  std::set<std::string> packageFamilyNameProcessed;
  for (const auto& k : userMsixKeys) {
    genMsixPrograms(k, packageFamilyNameProcessed, results);
  }

  return results;
}
} // namespace tables
} // namespace osquery
