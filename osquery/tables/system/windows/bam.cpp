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
#include <osquery/tables/system/windows/userassist.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/system/time.h>
#include <string>

namespace osquery {
namespace tables {

constexpr auto kBamRegPath =
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\%%\\%%";

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
