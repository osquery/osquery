/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/tables/system/windows/registry.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/system/time.h>
#include <string>

namespace osquery {
namespace tables {

constexpr auto kBamRegPath =
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\%%\\%%";

// Get last exeution time
auto last_execute_time(std::string& assist_data) {
  std::string last_run_string = assist_data.substr(0, 16);

  // Timestamp should always by 16 chars in length
  if (last_run_string.length() == 16) {
    // swap endianess
    std::reverse(last_run_string.begin(), last_run_string.end());

    for (std::size_t i = 0; i < last_run_string.length(); i += 2) {
      char temp = last_run_string[i];
      last_run_string[i] = last_run_string[i + 1];
      last_run_string[i + 1] = temp;
    }

    // Convert Windows FILETIME to UNIX Time
    unsigned long long last_run =
        tryTo<unsigned long long>(last_run_string, 16).takeOr(0ull);
    if (last_run == 0ull) {
      LOG(WARNING) << "Failed to convert FILETIME to UNIX time.";
      return std::string();
    }
    last_run = (last_run / 10000000) - 11644473600;
    std::time_t last_run_time = last_run;

    struct tm tm;
    gmtime_s(&tm, &last_run_time);

    auto time_str = platformAsctime(&tm);
    return time_str;
  } else {
    LOG(WARNING) << "Timestamp format is incorrect. Reported length is: "
                 << last_run_string.length();
    return std::string();
  }
}

QueryData genBam(QueryContext& context) {
  QueryData results;

  std::set<std::string> bam_keys;
  Row r;

  expandRegistryGlobs(kBamRegPath, bam_keys);

  for (const auto& rKey : bam_keys) {
    std::size_t bam_entry = rKey.find("UserSettings\\S");
    if (bam_entry != std::string::npos) {
      std::string sid = rKey.substr(rKey.find("S-1"));

      QueryData bam_entries;
      queryKey(rKey, bam_entries);

      for (const auto& bKey : bam_entries) {
        r["path"] = bKey.at("name");
        std::string last_run = bKey.at("data");

        if (bKey.at("name") == "SequenceNumber" ||
            bKey.at("name") == "Version") {
          r["last_execution_time"] = "";
          r["sid"] = sid;
        } else {
          r["last_execution_time"] = last_execute_time(last_run);
          r["sid"] = sid;
        }

        results.push_back(r);
      }
    }
  }
  return results;
}
} // namespace tables
} // namespace osquery
