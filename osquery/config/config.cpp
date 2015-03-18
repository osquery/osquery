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

  boost::unique_lock<boost::shared_mutex> lock(rw_lock);

  OsqueryConfig conf;
  if (!genConfig(conf).ok()) {
    return Status(1, "Cannot generate config");
  }

  // Override default arguments with flag options from config.
  for (const auto& option : conf.options) {
    if (Flag::isDefault(option.first)) {
      // Only override if option was NOT given as an argument.
      Flag::updateValue(option.first, option.second);
      VLOG(1) << "Setting flag option: " << option.first << "="
              << option.second;
    }
  }
  getInstance().cfg_ = conf;
  return Status(0, "OK");
}

Status Config::genConfig(std::vector<std::string>& conf) {
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
    for (const auto& it : response[0]) {
      conf.push_back(it.second);
    }
  }
  return Status(0, "OK");
}

inline void mergeOption(const tree_node& option, OsqueryConfig& conf) {
  conf.options[option.first.data()] = option.second.data();
  conf.all_data.add_child("options." + option.first, option.second);
}

inline void mergeAdditional(const tree_node& node, OsqueryConfig& conf) {
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
  std::vector<std::string> configs;
  auto s = genConfig(configs);
  if (!s.ok()) {
    return s;
  }

  for (const auto& config_data : configs) {
    std::stringstream json_data;
    json_data << config_data;

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
      // Parse each entry in yara. We iterate through additional_monitoring
      // twice because the yara section depends on entries in file_paths.
      for (const pt::ptree::value_type& v :
           tree.get_child("additional_monitoring")) {
        if (v.first == "yara") {
          for (const pt::ptree::value_type& file_cat : v.second) {
            // Make sure the category exists in file_paths.
            if (conf.eventFiles.find(file_cat.first) != conf.eventFiles.end()) {
              for (const pt::ptree::value_type& file : file_cat.second) {
                conf.yaraFiles[file_cat.first].push_back(file.second.get_value<std::string>());
              }
            }
          }
        }
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

const std::map<std::string, std::vector<std::string> >& Config::getYARAFiles() {
  boost::shared_lock<boost::shared_mutex> lock(rw_lock);
  return getInstance().cfg_.yaraFiles;

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

Status Config::checkConfig() {
  OsqueryConfig c;
  return genConfig(c);
}

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
