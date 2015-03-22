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

Status Config::load() {
  auto& config_plugin = Registry::getActive("config");
  if (!Registry::exists("config", config_plugin)) {
    return Status(1, "Missing config plugin " + config_plugin);
  }

  return genConfig();
}

Status Config::update(const std::map<std::string, std::string>& config) {
  // Request a unique write lock when updating config.
  boost::unique_lock<boost::shared_mutex> unique_lock(getInstance().mutex_);

  for (const auto& source : config) {
    getInstance().raw_[source.first] = source.second;
  }

  ConfigData conf;
  auto status = genConfig(conf);
  if (status.ok()) {
    getInstance().data_ = conf;
  }

  return status;
}

Status Config::genConfig() {
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

inline void mergeOption(const tree_node& option, ConfigData& conf) {
  conf.options[option.first.data()] = option.second.data();
  if (conf.all_data.count("options") > 0) {
    conf.all_data.get_child("options").erase(option.first);
  }
  conf.all_data.add_child("options." + option.first, option.second);
}

inline void mergeAdditional(const tree_node& node, ConfigData& conf) {
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
                         conf.files[category.first],
                         REC_LIST_FOLDERS | REC_EVENT_OPT);
    }
  }
}

inline void mergeScheduledQuery(const tree_node& node, ConfigData& conf) {
  // Read tree/JSON into a query structure.
  OsqueryScheduledQuery query;
  query.name = node.second.get<std::string>("name", "");
  query.query = node.second.get<std::string>("query", "");
  query.interval = node.second.get<int>("interval", 0);
  // Also store the raw node in the property tree list.
  conf.schedule.push_back(query);
  conf.all_data.add_child("scheduledQueries", node.second);
}

Status Config::genConfig(ConfigData& conf) {
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

Status Config::getMD5(std::string& hash_string) {
  // Request an accessor to our own config, outside of an update.
  ConfigDataInstance config;

  std::stringstream out;
  write_json(out, config.data());

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
