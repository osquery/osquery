/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/core.h>
#include <osquery/filesystem/fileops.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/tables/system/windows/registry.h>
#include <osquery/utils/conversions/tryto.h>
#include <string>

namespace osquery {
namespace tables {

// Get all Office applications and get all installed versions
constexpr auto kOfficePath = "\\Software\\Microsoft\\Office\\%\\%\\File MRU\\%";
constexpr auto kOffice365Path =
    "\\Software\\Microsoft\\Office\\%\\%\\User MRU\\%";

// Get non-office 365 documents in File MRU key
void officeData(QueryData& results,
                const std::set<std::string>& registry_results,
                const std::string& sid) {
  Row r;
  for (const auto& rKey : registry_results) {
    QueryData office_entries;
    queryKey(rKey, office_entries);
    for (const auto& aKey : office_entries) {
      // All file entries are start with "Item", skip entries that are not named "Item"
      if (aKey.at("name").find("Item") == std::string::npos) {
        continue;
      }
      // File MRU entries should also be over 20 characters long
      if (aKey.at("data").length() < 20) {
        LOG(INFO) << "File MRU entry malformed: " << aKey.at("data");
        continue;
      }
      std::string file_path = aKey.at("data");
      // File path starts with *
      r["path"] = file_path.substr(aKey.at("data").find("*") + 1);
      std::string version = rKey;
      r["version"] = version.substr(rKey.find("Office\\"), 11).substr(7);

      std::string application = rKey;
      std::string office_app = application.substr(rKey.find(r["version"]));
      r["application"] = office_app.substr(office_app.find("\\") + 1,
                                           office_app.find("\\File") - 5);

      // Last opened time stored in Big endian Windows FILETIME Hex format, also
      // starts with T
      std::string time_data =
          aKey.at("data").substr(aKey.at("data").find("T") + 1, 16);

      // Try to convert last open time string to ull
      unsigned long long last_open =
          tryTo<unsigned long long>(time_data, 16).takeOr(0ull);

      FILETIME file_time;
      ULARGE_INTEGER large_time;
      large_time.QuadPart = last_open;
      file_time.dwHighDateTime = large_time.HighPart;
      file_time.dwLowDateTime = large_time.LowPart;
      auto open_time = filetimeToUnixtime(file_time);

      r["last_opened_time"] = INTEGER(open_time);
      r["sid"] = sid;
      results.push_back(r);
    }
  }
}

// Get Office 365 documents in User MRU and File MRU keys
void office365Data(QueryData& results,
                   const std::set<std::string>& office_365_results,
                   const std::string& sid) {
  Row r;
  for (const auto& rKey : office_365_results) {
    std::string key = rKey;
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
      for (const auto& aKey : office_entries) {
        // All file entries are start with "Item", skip entries that are not
        // named "Item"
        if (aKey.at("name").find("Item") == std::string::npos) {
          continue;
        }
        // File MRU entries should be over 20 characters long
        if (aKey.at("data").length() < 20) {
          LOG(INFO) << "File MRU entry malformed: " << aKey.at("data");
          continue;
        }
        std::string file_path = aKey.at("data");
        // File path starts with *
        r["path"] = file_path.substr(aKey.at("data").find("*") + 1);

        std::string version = rKey;
        r["version"] = version.substr(rKey.find("Office\\"), 11).substr(7);

        std::string application = rKey;
        std::string office_app = application.substr(rKey.find(r["version"]));
        r["application"] = office_app.substr(office_app.find("\\") + 1,
                                             office_app.find("\\User") - 5);

        // Last opened time stored in Big endian Windows FILETIME Hex format,
        // also starts with T
        std::string time_data =
            aKey.at("data").substr(aKey.at("data").find("T") + 1, 16);

        // Try to convert last open time string to ull
        unsigned long long last_open =
            tryTo<unsigned long long>(time_data, 16).takeOr(0ull);

        FILETIME file_time;
        ULARGE_INTEGER large_time;
        large_time.QuadPart = last_open;
        file_time.dwHighDateTime = large_time.HighPart;
        file_time.dwLowDateTime = large_time.LowPart;
        auto open_time = filetimeToUnixtime(file_time);

        r["last_opened_time"] = INTEGER(open_time);
        r["sid"] = sid;
        results.push_back(r);
      }
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

    std::set<std::string> office_results;
    expandRegistryGlobs(office_path, office_results);
    std::string sid = uKey.at("name");
    officeData(results, office_results, sid);

    std::set<std::string> office_365_results;
    expandRegistryGlobs(office_365_path, office_365_results);
    office365Data(results, office_365_results, sid);
  }

  return results;
}
} // namespace tables
} // namespace osquery