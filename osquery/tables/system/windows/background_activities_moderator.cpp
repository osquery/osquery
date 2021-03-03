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
#include <osquery/logger/logger.h>
#include <osquery/tables/system/windows/registry.h>
#include <osquery/utils/conversions/windows/windows_time.h>

#include <string>

namespace osquery {
namespace tables {

constexpr auto kBamRegPath =
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\%%\\%%";

QueryData genBackgroundActivitiesModerator(QueryContext& context) {
  QueryData results;

  std::set<std::string> bam_keys;
  expandRegistryGlobs(kBamRegPath, bam_keys);

  for (const auto& rKey : bam_keys) {
    std::size_t bam_entry = rKey.find("UserSettings\\S");
    if (bam_entry == std::string::npos) {
      continue;
    }
    std::size_t key = rKey.find("S-1");
    if (key == std::string::npos) {
      continue;
    }
    std::string sid = rKey.substr(key);

    QueryData bam_entries;
    queryKey(rKey, bam_entries);
    for (const auto& bKey : bam_entries) {
      Row r;
      r["path"] = bKey.at("name");
      r["sid"] = sid;

      // BAM Registry entries contain "SequenceNumber and Version keys. These
      // keys do not have any data.
      if (r["path"] != "SequenceNumber" && r["path"] != "Version") {
        auto time_data = bKey.at("data").substr(0, 16);
        auto time_str = littleEndianToUnixTime(time_data);
        r["last_execution_time"] = BIGINT(time_str);
      }

      results.push_back(r);
    }
  }
  return results;
}
} // namespace tables
} // namespace osquery
