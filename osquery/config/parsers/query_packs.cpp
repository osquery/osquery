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

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "query_packs.h"

namespace pt = boost::property_tree;

namespace osquery {

typedef std::map<std::string, pt::ptree> query_pack_t;

inline pt::ptree queryPackSingleEntry(const pt::ptree& in) {
  // Prepare result to be returned
  pt::ptree out;
  out.put("query", in.get("query", ""));
  out.put("interval", in.get("interval", 0));
  out.put("platform", in.get("platform", ""));
  out.put("version", in.get("version", ""));
  out.put("description", in.get("description", "  "));
  out.put("value", in.get("value", ""));
  return out;
}

// Function to check if the pack is valid for this version of osquery.
// If the osquery version is greater or equal than the pack, it is good to go.
bool versionChecker(const std::string& pack, const std::string& version) {
  auto required_version = split(pack, ".");
  auto build_version = split(version, ".");

  size_t index = 0;
  for (const auto& chunk : build_version) {
    if (required_version.size() <= index) {
      return true;
    }
    try {
      if (std::stoi(chunk) < std::stoi(required_version[index])) {
        return false;
      }
    } catch (const std::invalid_argument& e) {
      if (chunk.compare(required_version[index]) < 0) {
        return false;
      }
    }
    index++;
  }
  return true;
}

query_pack_t queryPackParsePacks(const pt::ptree& raw_packs,
                                 bool check_platform,
                                 bool check_version) {
  query_pack_t result;

  // Iterate through all the pack elements
  for (auto const& one_pack : raw_packs) {
    // Grab query name and fields
    std::string pack_query_name = one_pack.first.data();

    // Get all the query fields
    auto pack_query_element = raw_packs.get_child(pack_query_name);
    auto single_pk = queryPackSingleEntry(pack_query_element);

    // Check if pack is valid for this system
    auto pk_platform = single_pk.get("platform", "");
    if (check_platform) {
      if (pk_platform.find(STR(OSQUERY_BUILD_PLATFORM)) == std::string::npos) {
        continue;
      }
    }

    // Check if current osquery version is equal or higher than needed
    auto pk_version = single_pk.get("version", "");
    if (check_version) {
      if (!versionChecker(pk_version, STR(OSQUERY_VERSION))) {
        continue;
      }
    }

    result[pack_query_name] = single_pk;
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
      LOG(WARNING) << "Error parsing Query Pack " << pack_name << ": "
                   << status.getMessage();
      continue;
    }

    // Get all the parsed elements from the pack JSON file
    if (pack_tree.count(pack_name) == 0) {
      continue;
    }

    // Get all the valid packs and return them in a map
    auto pack_file_element = pack_tree.get_child(pack_name);
    auto clean_packs = queryPackParsePacks(pack_file_element, true, true);

    // Iterate through the already parsed and valid packs
    for (const auto& pack : clean_packs) {
      // Preparing new queries to add to schedule
      std::string new_query = pack.second.get("query", "");
      int new_interval = pack.second.get("interval", 0);

      // Adding extracted pack to the schedule, if values valid
      if (!new_query.empty() && new_interval > 0) {
        bool exists_in_schedule = Config::checkScheduledQuery(new_query);

        // If query is already in schedule, do not add it again
        if (exists_in_schedule) {
          LOG(WARNING) << "Query already exist in the schedule: " << new_query;
        } else {
          // Adding a prefix to the pack queries, to be easily found in the
          // scheduled queries
          std::string pk_name = "pack_" + pack_name + "_" + pack.first;
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
