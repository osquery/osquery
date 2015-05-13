/*
 *  Copyright (c) 2015, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <map>
#include <string>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/config.h>
#include <osquery/logger.h>

#include "query_packs.h"

namespace pt = boost::property_tree;
namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

Status QueryPackConfigParserPlugin::update(const std::map<std::string, ConfigTree>& config) {
  Status status;
  const auto& pack_config = config.at("packs");
  if (pack_config.size() > 0) {
    for(auto const &pack_element : pack_config) {
      // Iterate through all the packs to get the configuration
      auto pack_name = std::string(pack_element.first.data());
      auto pack_path = std::string(pack_element.second.data());

      // Read each pack configuration in JSON
      pt::ptree pack_tree;
      status = osquery::parseJSON(pack_path, pack_tree);

      if (!status.ok()) {
        return status;
      }

      // Get all pack details
      const auto& pack_data = pack_tree.get_child(pack_name);
      if (pack_data.size() > 0) {
        std::string query = pack_data.get<std::string>("query", "");
        int interval = pack_data.get<int>("interval", 0);
        std::string platform = pack_data.get<std::string>("platform", "");
        std::string version = pack_data.get<std::string>("version", "");
        std::string description = pack_data.get<std::string>("description", "");
        std::string value = pack_data.get<std::string>("value", "");

        // Preparing new queries to add to schedule
        pt::ptree new_query;
        new_query.put("query", query);
        new_query.put("interval", interval);

        // Adding extracted pack to the schedule
        // TODO
      }
    }
  }
  return Status(0, "OK");
}

/// Call the simple Query Packs ConfigParserPlugin "packs".
REGISTER(QueryPackConfigParserPlugin, "config_parser", "packs");

}
}
