/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/tables.h>
#include <osquery/logger.h>
#include <osquery/filesystem.h>

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::map<std::string, std::string> kInstallHistoryKeys = {
  {"date", "date"},
  {"displayName", "display_name"},
  {"displayVersion", "display_version"},
  {"processName", "process_name"},
  {"contentType", "content_type"},
};

const std::string kInstallHistoryPath = "/Library/Receipts/InstallHistory.plist";

void genInstallHistoryEntry(const pt::ptree& entry, QueryData& results) {
  Row r;
  for (const auto& it : kInstallHistoryKeys) {
    r[it.second] = entry.get(it.first, "");
  }

  for (const auto& package_identifier : entry.get_child("packageIdentifiers")) {
    r["package_identifier"] = package_identifier.second.get<std::string>("");
    results.push_back(r);
   }
}

QueryData genInstallHistory(QueryContext& context) {
  QueryData results;
  pt::ptree tree;

  // The osquery::parsePlist method will reset/clear a property tree.
  // Keeping the data structure in a larger scope preserves allocations
  // between similar-sized trees.
  if (!osquery::parsePlist(kInstallHistoryPath, tree).ok()) {
    TLOG << "Error parsing install history plist: " << kInstallHistoryPath;
    return results;
  }

  if (tree.count("root") != 0) {
    for (const auto& it : tree.get_child("root")) {
      genInstallHistoryEntry(it.second, results);
    }
  }

  return results;
}
}
}
