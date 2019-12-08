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
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/system/time.h>
#include <string>

namespace osquery {
namespace tables {

constexpr auto kBamRegPath =
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\%%\\%%";

// Get last exeution time
auto lastExecute(std::string& time_data) {
  // Timestamp should always by 16 chars in length
  if (time_data.length() == 16) {
    // swap endianess
    std::reverse(time_data.begin(), time_data.end());

    for (std::size_t i = 0; i < time_data.length(); i += 2) {
      char temp = time_data[i];
      time_data[i] = time_data[i + 1];
      time_data[i + 1] = temp;
    }

    // Convert string to long long
    unsigned long long last_run =
        tryTo<unsigned long long>(time_data, 16).takeOr(0ull);
    if (last_run == 0ull) {
      LOG(WARNING) << "Failed to convert timestamp string to long long.";
      return 1LL;
    }
    FILETIME file_time;
    ULARGE_INTEGER large_time;
    large_time.QuadPart = last_run;
    file_time.dwHighDateTime = large_time.HighPart;
    file_time.dwLowDateTime = large_time.LowPart;
    auto last_time = filetimeToUnixtime(file_time);
    return last_time;
  } else {
    LOG(WARNING) << "Timestamp format is incorrect. Reported length is: "
                 << time_data.length();
    return 1LL;
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
          std::string time_data = last_run.substr(0, 16);
          auto time_str = lastExecute(time_data);
          if (time_str == 1LL) {
            r["last_execution_time"] = "";
          }
          r["last_execution_time"] = INTEGER(time_str);
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
