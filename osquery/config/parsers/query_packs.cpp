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

namespace pt = boost::property_tree;
namespace fs = boost::filesystem;

namespace osquery {
namespace tables {


/**
 * @brief A simple ConfigParserPlugin for a "packs" dictionary key.
 *
 */
class QueryPackConfigParserPlugin : public ConfigParserPlugin {
 public:
  /// Request "packs" top level key.
  std::vector<std::string> keys() { return {"packs"}; }

 private:
  /// Store the signatures and file_paths and compile the rules.
  Status update(const std::map<std::string, ConfigTree>& config);
};

pt::ptree QueryPackSingleEntry(const pt::ptree pack_data) {
  std::string query = pack_data.get<std::string>("query", "");
  int interval = pack_data.get<int>("interval", 0);
  std::string platform = pack_data.get<std::string>("platform", "");
  std::string version = pack_data.get<std::string>("version", "");
  std::string description = pack_data.get<std::string>("description", "");
  std::string value = pack_data.get<std::string>("value", "");

  pt::ptree result;
  result.put("query", query);
  result.put("interval", interval);
  result.put("platform", platform);
  result.put("version", version);
  result.put("description", description);
  result.put("value", value);

  return result;
}

Status QueryPackConfigParserPlugin::update(const std::map<std::string, ConfigTree>& config) {
  Status status;
  const auto& pack_config = config.at("packs");
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
    if (pack_data.size() == 0) {
      continue;
    }

    pt::ptree single_pk = QueryPackSingleEntry(pack_data);

    // Check if pack is valid for this system
    std::string pk_platform = single_pk.get<std::string>("platform");
    if (pk_platform.find(STR(OSQUERY_BUILD_PLATFORM)) == std::string::npos) {
      continue;
    }

    // Check if current osquery version is equal or higher than needed
    std::string pk_version = single_pk.get<std::string>("version");
    if (STR(OSQUERY_VERSION) < pk_version) {
      continue;
    }

    // Preparing new queries to add to schedule
    std::string new_query = single_pk.get<std::string>("query");
    int new_interval = single_pk.get<int>("interval");

    // Adding extracted pack to the schedule
    Config::addScheduledQuery(pack_name, new_query, new_interval);
  }
  return Status(0, "OK");
}

/// Call the simple Query Packs ConfigParserPlugin "packs".
REGISTER(QueryPackConfigParserPlugin, "config_parser", "packs");

}
}
