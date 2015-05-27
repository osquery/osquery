/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/registry.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>

#include "osquery/config/parsers/query_packs.h"

namespace osquery {
namespace tables {

typedef pt::ptree::value_type tree_node;

void genQueryPack(const tree_node& pack, QueryData& results) {
  Row r;
  // Packs are stored by name and contain configuration data.
  r["name"] = pack.first;
  r["path"] = pack.second.get("path", "");

  // There are optional restrictions on the set of queries applied pack-wide.
  auto pack_wide_version = pack.second.get("version", "");
  auto pack_wide_platform = pack.second.get("platform", "");

  // Iterate through each query in the pack.
  for (auto const& query : pack.second.get_child("queries")) {
    r["query_name"] = query.first;
    r["query"] = query.second.get("query", "");
    r["interval"] = INTEGER(query.second.get("interval", 0));
    r["description"] = query.second.get("description", "");
    r["value"] = query.second.get("value", "");

    // Set the version requirement based on the query-specific or pack-wide.
    if (query.second.count("version") > 0) {
      r["version"] = query.second.get("version", "");
    } else {
      r["version"] = pack_wide_platform;
    }

    // Set the platform requirement based on the query-specific or pack-wide.
    if (query.second.count("platform") > 0) {
      r["platform"] = query.second.get("platform", "");
    } else {
      r["platform"] = pack_wide_platform;
    }

    // Adding a prefix to the pack queries to differentiate packs from schedule.
    r["scheduled_name"] = "pack_" + r.at("name") + "_" + r.at("query_name");
    if (Config::checkScheduledQueryName(r.at("scheduled_name"))) {
      r["scheduled"] = INTEGER(1);
    } else {
      r["scheduled"] = INTEGER(0);
    }

    results.push_back(r);
  }
}

QueryData genOsqueryPacks(QueryContext& context) {
  QueryData results;

  // Get a lock on the config instance.
  ConfigDataInstance config;

  // Get the loaded data tree from global JSON configuration.
  const auto& packs_parsed_data = config.getParsedData("packs");

  // Iterate through all the packs to get each configuration and set of queries.
  for (auto const& pack : packs_parsed_data) {
    // Make sure the pack data contains queries.
    if (pack.second.count("queries") == 0) {
      continue;
    }
    genQueryPack(pack, results);
  }

  return results;
}
}
}
