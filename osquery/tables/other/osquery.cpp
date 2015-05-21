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

QueryData genOsqueryPacks(QueryContext& context) {
  Row r;
  QueryData results;
  ConfigDataInstance config;

  // Get the instance for the parser
  const auto& pack_parser = config.getParser("packs");
  if (pack_parser == nullptr) {
    return results;
  }
  const auto& queryPackParser = std::static_pointer_cast<QueryPackConfigParserPlugin>(pack_parser);
  if (queryPackParser == nullptr) {
    return results;
  }

  // Get the loaded data tree from global JSON configuration
  const auto& packs_parsed_data = config.getParsedData("packs");
  if (packs_parsed_data.count("packs") == 0) {
    return results;
  }

  // Iterate through all the packs to get the configuration
  for(auto const &pack_element : packs_parsed_data) {
    // Make sure the element has items
    if (pack_element.second.size() == 0) {
      continue;
    }
    std::string pack_name;
    std::string pack_path;

    // Find all the packs from loaded configuration
    for (auto const &conf_element : pack_element.second) {
      pack_name = std::string(conf_element.first.data());
      pack_path = std::string(conf_element.second.data());

      // Read each pack configuration in JSON
      pt::ptree pack_tree;
      Status status = osquery::parseJSON(pack_path, pack_tree);

      // Get all the parsed elements from the pack JSON file
      if (pack_tree.count(pack_name) == 0) {
        continue;
      }
      pt::ptree pack_file_element = pack_tree.get_child(pack_name);

      // Get all the valid packs and return them in a map
      std::map<std::string, pt::ptree> clean_packs = queryPackParser->QueryPackParsePacks(pack_file_element, false, false);

      // Iterate through the already parsed and valid packs
      std::map<std::string, pt::ptree>::iterator pk = clean_packs.begin();
      for(pk=clean_packs.begin(); pk!=clean_packs.end(); ++pk) {
        // Adding a prefix to the pack queries, to be easily found in the scheduled queries
        std::string pk_name = "pack_" + pack_name + "_" + pk->first;
        pt::ptree pk_data = pk->second;

        // Query data to return as Row
        r["query_name"] = TEXT(pk->first);
        r["name"] = TEXT(pack_name);
        r["path"] = TEXT(pack_path);
        r["query"] = TEXT(pk_data.get<std::string>("query"));
        r["interval"] = INTEGER(pk_data.get<int>("interval"));
        r["platform"] = TEXT(pk_data.get<std::string>("platform"));
        r["version"] = TEXT(pk_data.get<std::string>("version"));
        r["description"] = TEXT(pk_data.get<std::string>("description"));
        r["value"] = TEXT(pk_data.get<std::string>("value"));
        r["scheduled_name"] = TEXT(pk_name);
        int scheduled = Config::checkScheduledQuery(r["query"]) ? 1 : 0;
        r["scheduled"] = INTEGER(scheduled);

        results.push_back(r);
      }
    }
  }

  return results;
}
}
}
