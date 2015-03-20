/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <mutex>
#include <sstream>

#include <boost/thread/shared_mutex.hpp>

#include <osquery/config.h>
#include <osquery/flags.h>
#include <osquery/hash.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

namespace pt = boost::property_tree;

typedef pt::ptree::value_type tree_node;
typedef std::map<std::string, std::vector<std::string> > EventFileMap_t;

namespace osquery {

CLI_FLAG(string, config_plugin, "filesystem", "Config plugin name");

// This lock is used to protect the entirety of the OSqueryConfig struct
// Is should be used when ever accessing the structs members, reading or
// writing.
static boost::shared_mutex rw_lock;

Status Config::load() {
  auto& config_plugin = Registry::getActive("config");
  if (!Registry::exists("config", config_plugin)) {
    return Status(1, "Missing config plugin " + config_plugin);
  }

  return genConfig();
}

Status Config::update(const std::map<std::string, std::string>& config) {
  boost::unique_lock<boost::shared_mutex> lock(rw_lock);

  for (const auto& source : config) {
    getInstance().raw_[source.first] = source.second;
  }

  OsqueryConfig conf;
  auto status = genConfig(conf);
  if (status.ok()) {
    getInstance().cfg_ = conf;
  }
  return status;
}

Status Config::genConfig() {
  auto& config_plugin = Registry::getActive("config");
  if (!Registry::exists("config", config_plugin)) {
    return Status(1, "Missing config plugin " + config_plugin);
  }

  PluginResponse response;
  auto status = Registry::call("config", {{"action", "genConfig"}}, response);
  if (!status.ok()) {
    return status;
  }

  if (response.size() > 0) {
    return update(response[0]);
  }
  return Status(0, "OK");
}

inline void mergeOption(const tree_node& option, OsqueryConfig& conf) {
  conf.options[option.first.data()] = option.second.data();
  if (conf.all_data.count("options") > 0) {
    conf.all_data.get_child("options").erase(option.first);
  }
  conf.all_data.add_child("options." + option.first, option.second);
}

inline void mergeAdditional(const tree_node& node, OsqueryConfig& conf) {
  if (conf.all_data.count("additional_monitoring") > 0) {
    conf.all_data.get_child("additional_monitoring").erase(node.first);
  }
  conf.all_data.add_child("additional_monitoring." + node.first, node.second);

  // Support special merging of file paths.
  if (node.first != "file_paths") {
    return;
  }

  for (const auto& category : node.second) {
    for (const auto& path : category.second) {
      resolveFilePattern(path.second.data(),
                         conf.eventFiles[category.first],
                         REC_LIST_FOLDERS | REC_EVENT_OPT);
    }
  }
}

inline void mergeScheduledQuery(const tree_node& node, OsqueryConfig& conf) {
  // Read tree/JSON into a query structure.
  OsqueryScheduledQuery query;
  query.name = node.second.get<std::string>("name", "");
  query.query = node.second.get<std::string>("query", "");
  query.interval = node.second.get<int>("interval", 0);
  // Also store the raw node in the property tree list.
  conf.scheduledQueries.push_back(query);
  conf.all_data.add_child("scheduledQueries", node.second);
}

Status Config::genConfig(OsqueryConfig& conf) {
  for (const auto& source : getInstance().raw_) {
    std::stringstream json_data;
    json_data << source.second;

    pt::ptree tree;
    pt::read_json(json_data, tree);

    if (tree.count("scheduledQueries") > 0) {
      for (const auto& node : tree.get_child("scheduledQueries")) {
        mergeScheduledQuery(node, conf);
      }
    }

    if (tree.count("additional_monitoring") > 0) {
      for (const auto& node : tree.get_child("additional_monitoring")) {
        mergeAdditional(node, conf);
      }
    }

    if (tree.count("options") > 0) {
      for (const auto& option : tree.get_child("options")) {
        mergeOption(option, conf);
      }
    }
  }
  return Status(0, "OK");
}

std::vector<OsqueryScheduledQuery> Config::getScheduledQueries() {
  boost::shared_lock<boost::shared_mutex> lock(rw_lock);
  return getInstance().cfg_.scheduledQueries;
}

std::map<std::string, std::vector<std::string> > Config::getWatchedFiles() {
  boost::shared_lock<boost::shared_mutex> lock(rw_lock);
  return getInstance().cfg_.eventFiles;
}

pt::ptree Config::getEntireConfiguration() {
  boost::shared_lock<boost::shared_mutex> lock(rw_lock);
  return getInstance().cfg_.all_data;
}

Status Config::getMD5(std::string& hash_string) {
  std::stringstream out;
  write_json(out, getEntireConfiguration());

  hash_string = osquery::hashFromBuffer(
      HASH_TYPE_MD5, (void*)out.str().c_str(), out.str().length());

  return Status(0, "OK");
}

Status Config::checkConfig() { return load(); }

Status ConfigPlugin::call(const PluginRequest& request,
                          PluginResponse& response) {
  if (request.count("action") == 0) {
    return Status(1, "Config plugins require an action in PluginRequest");
  }

  if (request.at("action") == "genConfig") {
    std::map<std::string, std::string> config;
    auto stat = genConfig(config);
    response.push_back(config);
    return stat;
  }
  return Status(1, "Config plugin action unknown: " + request.at("action"));
}
}
