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

namespace osquery {

pt::ptree QueryPackSingleEntry(const pt::ptree& pack_data) {
  // Extract all the pack fields
  std::string query = pack_data.get<std::string>("query", "");
  int interval = pack_data.get<int>("interval", 0);
  std::string platform = pack_data.get<std::string>("platform", "");
  std::string version = pack_data.get<std::string>("version", "");
  std::string description = pack_data.get<std::string>("description", "");
  std::string value = pack_data.get<std::string>("value", "");

  // Prepare result to be returned
  pt::ptree result;
  result.put("query", query);
  result.put("interval", interval);
  result.put("platform", platform);
  result.put("version", version);
  result.put("description", description);
  result.put("value", value);

  return result;
}

// Function to check if the pack is valid for this version of osquery.
// If the osquery version is greater or equal than the pack, it is good to go.
bool versionChecker(const std::string& pack_version) {
  std::vector<std::string> version_chunk = split(pack_version, ".");
  std::vector<std::string> osquery_chunk = split(OSQUERY_VERSION, ".");

  // This is the logic for versioning used
  // 1.2.3
  // | | |----> build
  // | |------> minor
  // |--------> major
  //
  // [0]: major
  // [1]: minor
  // [2]: build

  if (version_chunk.size() != 3 || osquery_chunk.size() != 3) {
    return false;
  }

  // Now we compare major first
  if (std::stoi(osquery_chunk[0]) > std::stoi(version_chunk[0])) {
    return true;
  }
  if (std::stoi(osquery_chunk[0]) < std::stoi(version_chunk[0])) {
    return false;
  }
  if (std::stoi(osquery_chunk[0]) == std::stoi(version_chunk[0])) {
    // We need to check minor
    if (std::stoi(osquery_chunk[1]) > std::stoi(version_chunk[1])) {
      return true;
    }
    if (std::stoi(osquery_chunk[1]) < std::stoi(version_chunk[1])) {
      return false;
    }
    if (std::stoi(osquery_chunk[1]) == std::stoi(version_chunk[1])) {
      // Last check is the build
      if (std::stoi(osquery_chunk[2]) >= std::stoi(version_chunk[2])) {
        return true;
      }
      if (std::stoi(osquery_chunk[2]) < std::stoi(version_chunk[2])) {
        return false;
      }
    }
  }

  return false;
}

std::map<std::string, pt::ptree>
QueryPackConfigParserPlugin::QueryPackParsePacks(const pt::ptree& raw_packs,
                                                 bool check_platform,
                                                 bool check_version) {
  std::map<std::string, pt::ptree> result;

  // Iterate through all the pack elements
  for (auto const& one_pack : raw_packs) {
    // Grab query name and fields
    std::string pack_query_name = one_pack.first.data();
    pt::ptree pack_query_element = raw_packs.get_child(pack_query_name);

    // Get all the query fields
    pt::ptree single_pk = QueryPackSingleEntry(pack_query_element);

    // Check if pack is valid for this system
    std::string pk_platform = single_pk.get<std::string>("platform");
    if (check_platform) {
      if (pk_platform.find(STR(OSQUERY_BUILD_PLATFORM)) == std::string::npos) {
        continue;
      }
    }

    // Check if current osquery version is equal or higher than needed
    std::string pk_version = single_pk.get<std::string>("version");
    if (check_version) {
      if (!versionChecker(pk_version)) {
        continue;
      }
    }

    result.insert(
        std::pair<std::string, pt::ptree>(pack_query_name, single_pk));
  }

  return result;
}

Status QueryPackConfigParserPlugin::update(
    const std::map<std::string, ConfigTree>& config) {
  Status status;

  const auto& pack_config = config.at("packs");

  data_.add_child("packs", pack_config);

  // Iterate through all the packs to get the configuration
  for (auto const& pack_element : pack_config) {
    auto pack_name = std::string(pack_element.first.data());
    auto pack_path = std::string(pack_element.second.data());

    // Read each pack configuration in JSON
    pt::ptree pack_tree;
    status = osquery::parseJSON(pack_path, pack_tree);

    if (!status.ok()) {
      LOG(WARNING) << "Problem parsing JSON pack: " << status.getCode() << " - "
                   << status.getMessage();
      continue;
    }

    // Get all the parsed elements from the pack JSON file
    if (pack_tree.count(pack_name) == 0) {
      continue;
    }
    pt::ptree pack_file_element = pack_tree.get_child(pack_name);

    // Get all the valid packs and return them in a map
    std::map<std::string, pt::ptree> clean_packs =
        QueryPackParsePacks(pack_file_element, true, true);

    // Iterate through the already parsed and valid packs
    std::map<std::string, pt::ptree>::iterator pk = clean_packs.begin();
    for (pk = clean_packs.begin(); pk != clean_packs.end(); ++pk) {
      // Adding a prefix to the pack queries, to be easily found in the
      // scheduled queries
      std::string pk_name = "pack_" + pack_name + "_" + pk->first;
      pt::ptree pk_data = pk->second;

      // Preparing new queries to add to schedule
      std::string new_query = pk_data.get<std::string>("query");
      int new_interval = pk_data.get<int>("interval");

      // Adding extracted pack to the schedule, if values valid
      if (!new_query.empty() && new_interval > 0) {
        bool exists_in_schedule = Config::checkScheduledQuery(new_query);

        // If query is already in schedule, do not add it again
        if (exists_in_schedule) {
          LOG(WARNING) << "Query already exist in the schedule: " << new_query;
        } else {
          Config::addScheduledQuery(pk_name, new_query, new_interval);
        }
      }
    }
  }

  return Status(0, "OK");
}

/// Call the simple Query Packs ConfigParserPlugin "packs".
REGISTER(QueryPackConfigParserPlugin, "config_parser", "packs");
}
