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
#include <osquery/logger/logger.h>
#include <osquery/tables/system/windows/registry.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/windows_time.h>

#include <string>

namespace osquery {
namespace tables {

// Get all Office applications and get all installed versions
constexpr auto kOfficePath = "\\Software\\Microsoft\\Office\\%\\%\\File MRU\\%";
constexpr auto kOffice365Path =
    "\\Software\\Microsoft\\Office\\%\\%\\User MRU\\%";

// Parse all the office MRU entries.
void parseOfficeData(QueryData& results,
                     const Row& entry,
                     const std::string& sid,
                     const std::string& office_version) {
  auto item = entry.find("name");
  // All file entries start with "Item", skip entries that are not named
  // "Item"
  if (item->second.find("Item") == std::string::npos) {
    return;
  }

  // MRU entries should also be over 20 characters long
  auto data = entry.find("data");
  auto& file_path = data->second;
  if (file_path.length() < 20) {
    LOG(WARNING) << "MRU entry malformed: " << file_path;
    return;
  }

  Row r;
  // File path starts with *
  r["path"] = file_path.substr(file_path.find("*") + 1);

  // Extract the office application version from the registry path
  auto version = office_version;
  r["version"] = version.substr(office_version.find("Office\\"), 11).substr(7);

  // Extract the office application name from the registry path
  auto application = office_version;
  auto office_app = application.substr(office_version.find(r["version"]));
  r["application"] = office_app.substr(office_app.find("\\") + 1,
                                       office_app.find(" MRU") - 10);

  // Last opened time stored in Big endian Windows FILETIME Hex format, also
  // starts with T
  auto time_data = file_path.substr(file_path.find("T") + 1, 16);

  // Try to convert last open time string to ull
  unsigned long long last_open =
      tryTo<unsigned long long>(time_data, 16).takeOr(0ull);

  FILETIME file_time;
  ULARGE_INTEGER large_time;
  large_time.QuadPart = last_open;
  file_time.dwHighDateTime = large_time.HighPart;
  file_time.dwLowDateTime = large_time.LowPart;
  auto open_time = filetimeToUnixtime(file_time);

  r["last_opened_time"] = BIGINT(open_time);
  r["sid"] = sid;
  results.push_back(r);
}

// Get non-office 365 documents in File MRU key
void officeData(QueryData& results,
                const std::string& office_data,
                const std::string& sid) {
  QueryData office_entries;
  queryKey(office_data, office_entries);
  for (const auto& entry : office_entries) {
    parseOfficeData(results, entry, sid, office_data);
  }
}

// Get Office 365 documents in User MRU and File MRU keys
void office365Data(QueryData& results,
                   const std::string& office_365_data,
                   const std::string& sid) {
  std::string key = office_365_data;
  std::set<std::string> office_365_results_files;
  // Iterate through all User MRU entries
  expandRegistryGlobs(key.append("\\%"), office_365_results_files);
  for (const auto& fKey : office_365_results_files) {
    // User accounts should have "_" in them, skip all keys that do not have
    // "_"
    if (fKey.find("_") == std::string::npos) {
      continue;
    }
    QueryData office_entries;
    std::string final_key = fKey;
    queryKey(final_key.append("\\File MRU"), office_entries);
    for (const auto& entry : office_entries) {
      parseOfficeData(results, entry, sid, office_365_data);
    }
  }
}

QueryData genOfficeMru(QueryContext& context) {
  QueryData results;
  QueryData users;

  queryKey("HKEY_USERS", users);
  for (const auto& uKey : users) {
    auto keyType = uKey.find("type");
    auto keyPath = uKey.find("path");

    if (keyType == uKey.end() || keyPath == uKey.end()) {
      continue;
    }

    std::string office_path = keyPath->second + kOfficePath;
    std::string office_365_path = keyPath->second + kOffice365Path;
    std::string sid = uKey.at("name");

    std::set<std::string> office_results;
    expandRegistryGlobs(office_path, office_results);
    for (const auto& office_data : office_results) {
      officeData(results, office_data, sid);
    }

    std::set<std::string> office_365_results;
    expandRegistryGlobs(office_365_path, office_365_results);
    for (const auto& office_365_data : office_365_results) {
      office365Data(results, office_365_data, sid);
    }
  }
  return results;
}
} // namespace tables
} // namespace osquery
