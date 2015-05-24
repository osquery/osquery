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

void genQueryPack(const tree_node& pack_element, QueryData& results) {
  // Find all the packs from loaded configuration
  for (auto const& conf_element : pack_element.second) {
    auto pack_name = std::string(conf_element.first.data());
    auto pack_path = std::string(conf_element.second.data());

    // Read each pack configuration in JSON
    pt::ptree pack_tree;
    Status status = osquery::parseJSON(pack_path, pack_tree);

    // Get all the parsed elements from the pack JSON file
    if (pack_tree.count(pack_name) == 0) {
      continue;
    }

    // Get all the valid packs and return them in a map
    auto pack_file_element = pack_tree.get_child(pack_name);
    auto clean_packs = queryPackParsePacks(pack_file_element, false, false);

    // Iterate through the already parsed and valid packs
    for (const auto& pack : clean_packs) {
      Row r;

      // Query data to return as Row
      r["name"] = pack_name;
      r["path"] = pack_path;
      r["query_name"] = pack.first;
      r["query"] = pack.second.get("query", "");
      r["interval"] = INTEGER(pack.second.get("interval", 0));
      r["platform"] = pack.second.get("platform", "");
      r["version"] = pack.second.get("version", "");
      r["description"] = pack.second.get("description", "");
      r["value"] = pack.second.get("value", "");

      // Adding a prefix to the pack queries, to be easily found in the
      // scheduled queries
      r["scheduled_name"] = "pack_" + pack_name + "_" + pack.first;
      int scheduled =
          Config::checkScheduledQueryName(r.at("scheduled_name")) ? 1 : 0;
      r["scheduled"] = INTEGER(scheduled);

      results.push_back(r);
    }
  }
}

QueryData genOsqueryPacks(QueryContext& context) {
  QueryData results;

  // Get a lock on the config instance
  ConfigDataInstance config;

  // Get the loaded data tree from global JSON configuration
  const auto& packs_parsed_data = config.getParsedData("packs");
  if (packs_parsed_data.count("packs") == 0) {
    return results;
  }

  // Iterate through all the packs to get the configuration
  for (auto const& pack_element : packs_parsed_data) {
    // Make sure the element has items
    if (pack_element.second.size() == 0) {
      continue;
    }
    genQueryPack(pack_element, results);
  }

  return results;
}
}
}
