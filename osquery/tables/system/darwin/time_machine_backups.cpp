// Copyright 2004-present Facebook. All Rights Reserved.

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
const std::string kSnapshotKey = "SnapshotDates";

QueryData genTimeMachineBackups(QueryContext& context) {
  QueryData results;
  pt::ptree tree;
  Status s = osquery::parsePlist(kTimeMachinePrefs, tree);
  if (!s.ok()) {
    return results;
  }

  if (tree.count(kDestinationKey)) {
    const pt::ptree& destinations = tree.get_child(kDestinationKey);
    for (const auto& dest : destinations) {
      if (!dest.second.count(kSnapshotKey)) {
        continue;
      }
      const auto& snapshots = dest.second.get_child(kSnapshotKey);
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
}
}
