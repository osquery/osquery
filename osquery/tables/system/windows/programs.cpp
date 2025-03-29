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
#include <osquery/filesystem/fileops.h>
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
std::string extractTagContent(const std::string& xml,
                              const std::string& tagName) {
  std::regex tagRegex("<" + tagName + "[^>]*>(.*?)<\\/" + tagName + ">");
  std::smatch match;

  if (std::regex_search(xml, match, tagRegex)) {
    // match[0] is the entire tag with contents <TagName>contents</TagName>
    // match[1] is the contents of the tag
    return match[1];
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

std::string identifyingNumberFromPackageFullName(
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

void keyEnumPrograms(const std::string& key,
                     std::set<std::string>& processed,
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

void genMsixPrograms(const std::string& key, QueryData& results) {
  std::set<std::string> packageFamilyNameProcessed;
  QueryData regResults;
  queryKey(key, regResults);
  for (const auto& rKey : regResults) {
    // Each subkey represents a package, skip if not a subkey
    if (rKey.at("type") != "subkey") {
      continue;
    }
    const auto& regPath = rKey.at("path");
    const auto& regPackageFullName = rKey.at("name");

    // Get all registry entires for the package
    QueryData appResults;
    queryKey(regPath, appResults);
    Row result;

    result["identifying_number"] =
        identifyingNumberFromPackageFullName(regPackageFullName);

    for (const auto& aKey : appResults) {
      auto name = aKey.find("name");

      if (name->second == "PackageRootFolder") {
        result["install_location"] = aKey.at("data");
        std::string filePath =
            result["install_location"] + "\\AppxManifest.xml";

        std::ifstream xmlFile(filePath);
        if (!xmlFile) {
          // Skip this package, as we cannot find the manifest file
          // We can extract some information from the registry key
          // <PackageName>_<Version>_<Architecture>__<PublisherHash>
          // Example:
          // MSTeams_25060.205.3499.6849_arm64__8wekyb3d8bbwe
          // But all proper MSIX packages have an AppxManifest.xml file
          LOG(VERBOSE) << "Cannot find manifest file:'" + regPath + "'";
          result.clear();
          continue;
        }

        // btime "Birth Time"
        // When a file is first created, btime is set and does not change
        // ::Warning:: not all filesystems support btime
        // Older file systems such as ext3 or FAT32 will have this missing
        WINDOWS_STAT file_stat;
        auto rtn = platformStat(filePath.c_str(), &file_stat);
        if (rtn.ok()) {
          result["install_date"] = formatTimestampToDate(file_stat.btime);
        }

        std::string line;
        std::string buffer;
        while (std::getline(xmlFile, line)) {
          if (line.find("<Identity") != std::string::npos) {
            buffer += line;

            // Continue reading lines until the tag is complete (contains "/>")
            while (buffer.find("/>") == std::string::npos &&
                   std::getline(xmlFile, line)) {
              buffer += line;
            }
            auto attributes = parseAttributes(buffer);
            result["name"] = attributes["Name"];
            result["publisher"] = attributes["Publisher"];
            result["version"] = attributes["Version"];

            buffer.clear();
          }

          if (line.find("<Properties") != std::string::npos) {
            buffer += line;

            // Continue reading lines until the tag is complete (contains
            // "</Properties>")
            while (buffer.find("</Properties>") == std::string::npos &&
                   std::getline(xmlFile, line)) {
              buffer += line;
            }
            auto displayName = extractTagContent(buffer, "DisplayName");
            auto publisherDisplayName =
                extractTagContent(buffer, "PublisherDisplayName");

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

            buffer.clear();

            // done parsing the appxmanifest.xml file for the things we need, so
            // we don't have to continue reading the file
            break;
          }
        }

        xmlFile.close();
      }
    } // end processing package registry entry

    if (!result.empty()) {
      auto packageKey = result["identifying_number"];
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

  std::set<std::string> processedPrograms;
  for (const auto& k : programKeys) {
    keyEnumPrograms(k, processedPrograms, results);
  }

  std::set<std::string> userMsixKeys;
  expandRegistryGlobs(
      "HKEY_USERS\\%\\Software\\Classes\\Local "
      "Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Reposi"
      "tory\\Packages",
      userMsixKeys);

  for (const auto& k : userMsixKeys) {
    genMsixPrograms(k, results);
  }

  return results;
}
} // namespace tables
} // namespace osquery
