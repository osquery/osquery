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
const std::string kAliasKey = "BackupAlias";
const std::string kDestinationIdKey = "DestinationID";
const std::string kBytesUsedKey = "BytesUsed";
const std::string kBytesAvailableKey = "BytesAvailable";
const std::string kRVUUID = "RootVolumeUUID";
const std::string kConsistencyScanDate = "ConsistencyScanDate";
const std::string kLKEncryptionState = "LastKnownEncryptionState";

QueryData genTimeMachineDestinations(QueryContext& context) {
  QueryData results;
  pt::ptree tree;
  Status s = osquery::parsePlist(kTimeMachinePrefs, tree);
  if (!s.ok()) {
    return results;
  }

  if (tree.count(kDestinationKey)) {
    auto destinations = tree.get_child(kDestinationKey);
    for (const auto& dest : destinations) {
      Row r;
      r["destination_id"] = dest.second.get(kDestinationIdKey, "");
      r["consistency_scan_date"] = dest.second.get(kConsistencyScanDate, "");
      r["root_volume_uuid"] = dest.second.get(kRVUUID, "");
      r["bytes_used"] = dest.second.get(kBytesUsedKey, "");
      r["bytes_available"] = dest.second.get(kBytesAvailableKey, "");
      r["encryption"] = dest.second.get(kLKEncryptionState, "");

      std::string strAliasData =
          osquery::base64Decode(dest.second.get(kAliasKey, ""));
      if (strAliasData.size() < 11) {
        results.push_back(r);
        continue;
      }
      unsigned short usAliasLen = (strAliasData[4] << 8) + strAliasData[5];
      if (usAliasLen != strAliasData.size()) {
        results.push_back(r);
        continue;
      }
      unsigned char ucNameLen = strAliasData[10];
      if (ucNameLen + 11 <= strAliasData.size()) {
        r["alias"] = strAliasData.substr(11, ucNameLen);
      }
      results.push_back(r);
    }
  }
  return results;
}
}
}
