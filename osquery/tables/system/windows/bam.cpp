/**
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
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\%%\\";

// Get last exeution time
auto last_execute_time(std::string& assist_data) {
  std::string last_run_string = assist_data.substr(0, 16);

  // swap endianess
  std::reverse(last_run_string.begin(), last_run_string.end());

  char temp;
  for (std::size_t i = 0; i < last_run_string.length(); i += 2) {
    temp = last_run_string[i];
    last_run_string[i] = last_run_string[i + 1];
    last_run_string[i + 1] = temp;
  }

  // Convert Windows FILETIME to UNIX Time
  unsigned long long last_run = std::stoull(last_run_string.c_str(), 0, 16);
  last_run = (last_run / 10000000) - 11644473600;

  std::time_t last_run_time = last_run;

  struct tm tm;
  gmtime_s(&tm, &last_run_time);

  auto time_str = platformAsctime(&tm);
  return time_str;
}

QueryData genBam(QueryContext& context) {
  QueryData results;

  std::set<std::string> bam_keys;
  std::string kFullRegPath;
  Row r;

  expandRegistryGlobs(kBamRegPath, bam_keys);

  for (const auto& rKey : bam_keys) {
    std::size_t bam_entry = rKey.find("UserSettings\\S");
    if (bam_entry != std::string::npos) {
      std::string sid =  rKey.substr(rKey.find("S-1"));

      kFullRegPath = rKey;
        QueryData bam_entries;
        queryKey(kFullRegPath, bam_entries);

        for (const auto& bKey : bam_entries) {
          if (bKey.at("name") == "Version" ||
              bKey.at("name") == "SequenceNumber") {
            continue;
		  }
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
      } else {
      LOG(WARNING) << "No BAM Registry Key found";
	}
  }

  return results;
}
} // namespace tables
} // namespace osquery
