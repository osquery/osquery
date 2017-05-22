/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>

#include <boost/property_tree/ptree.hpp>

#include <osquery/filesystem.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::string kTimeMachinePrefs =
    "/Library/Preferences/com.apple.TimeMachine.plist";
const std::string kDestinationKey = "Destinations";
const std::string kDestinationIdKey = "DestinationID";

QueryData genTimeMachineBackups(QueryContext& context) {
  QueryData results;
  pt::ptree tree;
  if (!osquery::parsePlist(kTimeMachinePrefs, tree)) {
    return results;
  }

  if (tree.count(kDestinationKey)) {
    const pt::ptree& destinations = tree.get_child(kDestinationKey);
    for (const auto& dest : destinations) {
      if (!dest.second.count("SnapshotDates")) {
        continue;
      }
      const auto& snapshots = dest.second.get_child("SnapshotDates");
      for (const auto& snapshot : snapshots) {
        Row r;
        r["destination_id"] = dest.second.get(kDestinationIdKey, "");
        r["backup_date"] = snapshot.second.get_value("");
        results.push_back(r);
      }
    }
  }
  return results;
}

QueryData genTimeMachineDestinations(QueryContext& context) {
  QueryData results;
  pt::ptree tree;
  if (!osquery::parsePlist(kTimeMachinePrefs, tree)) {
    return results;
  }

  if (tree.count(kDestinationKey) == 0) {
    return results;
  }
  auto destinations = tree.get_child(kDestinationKey);
  for (const auto& dest : destinations) {
    Row r;
    r["destination_id"] = dest.second.get(kDestinationIdKey, "");
    r["consistency_scan_date"] = dest.second.get("ConsistencyScanDate", "");
    r["root_volume_uuid"] = dest.second.get("RootVolumeUUID", "");
    r["bytes_used"] = dest.second.get("BytesUsed", "");
    r["bytes_available"] = dest.second.get("BytesAvailable", "");
    r["encryption"] = dest.second.get("LastKnownEncryptionState", "");

    std::string alias_data =
        osquery::base64Decode(dest.second.get("BackupAlias", ""));
    if (alias_data.size() < 11) {
      results.push_back(r);
      continue;
    }
    unsigned short alias_len = (alias_data[4] << 8) + alias_data[5];
    if (alias_len != alias_data.size()) {
      results.push_back(r);
      continue;
    }
    unsigned char name_len = alias_data[10];
    if (name_len + 11 <= alias_data.size()) {
      r["alias"] = alias_data.substr(11, name_len);
    }
    results.push_back(r);
  }
  return results;
}
}
}
