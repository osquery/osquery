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

namespace pt = boost::property_tree;

namespace osquery {

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
  Status update(const ConfigTreeMap& config);
};

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
      } else if (std::stoi(chunk) > std::stoi(required_version[index])) {
        return true;
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

// Perform a string string search for the actual platform within the required.
bool platformChecker(const std::string& required, const std::string& platform) {
  // Match if platform is 'ubuntu12' and required is 'ubuntu'.
  // Do not match if platform is 'ubuntu12' and required is 'ubuntu14'.
#ifdef __linux__
  if (required.find("linux") != std::string::npos) {
    return true;
  }
#endif
  if (required.find("any") != std::string::npos ||
      required.find("all") != std::string::npos) {
    return true;
  }
  return (required.find(platform) != std::string::npos);
}

Status parsePack(const std::string& name, const pt::ptree& data) {
  if (data.count("queries") == 0) {
    return Status(0, "Pack contains no queries");
  }

  // Check the pack-global minimum SDK version and platform.
  auto version = data.get("version", "");
  if (version.size() > 0 && !versionChecker(version, kSDKVersion)) {
    return Status(0, "Minimum SDK version not met");
  }

  auto platform = data.get("platform", "");
  if (platform.size() > 0 && !platformChecker(platform, kSDKPlatform)) {
    return Status(0, "Platform version mismatch");
  }

  // For each query in the pack's queries, check their version/platform.
  for (const auto& query : data.get_child("queries")) {
    auto query_string = query.second.get("query", "");
    if (Config::checkScheduledQuery(query_string)) {
      VLOG(1) << "Query pack " << name
              << " contains a duplicated query: " << query.first;
      continue;
    }

    // Check the specific query's required version.
    version = query.second.get("version", "");
    if (version.size() > 0 && !versionChecker(version, kSDKVersion)) {
      continue;
    }

    // Check the specific query's required platform.
    platform = query.second.get("platform", "");
    if (platform.size() > 0 && !platformChecker(platform, kSDKPlatform)) {
      continue;
    }

    // Hope there is a supplied/non-0 query interval to apply this query pack
    // query to the osquery schedule.
    auto query_interval = query.second.get("interval", 0);
    if (query_interval > 0) {
      auto query_name = "pack_" + name + "_" + query.first;
      Config::addScheduledQuery(query_name, query_string, query_interval);
    }
  }

  return Status(0, "OK");
}

Status QueryPackConfigParserPlugin::update(const ConfigTreeMap& config) {
  // Iterate through all the packs to get the configuration.
  for (auto const& pack : config.at("packs")) {
    auto pack_name = std::string(pack.first.data());
    auto pack_path = std::string(pack.second.data());

    // Read each pack configuration in JSON
    pt::ptree pack_data;
    auto status = osquery::parseJSON(pack_path, pack_data);
    if (!status.ok()) {
      LOG(WARNING) << "Error parsing Query Pack " << pack_name << ": "
                   << status.getMessage();
      continue;
    }

    // Parse the pack, meaning compare version/platform requirements and
    // check the sanity of each query in the pack's queries.
    status = parsePack(pack_name, pack_data);
    if (!status.ok()) {
      return status;
    }

    // Save the queries list for table-based introspection.
    data_.put_child(pack_name, pack_data);
    // Record the pack path.
    data_.put(pack_name + ".path", pack_path);
  }

  return Status(0, "OK");
}

/// Call the simple Query Packs ConfigParserPlugin "packs".
REGISTER_INTERNAL(QueryPackConfigParserPlugin, "config_parser", "packs");
}
