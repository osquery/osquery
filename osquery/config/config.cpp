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

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/thread/shared_mutex.hpp>

#include <osquery/config.h>
#include <osquery/flags.h>
#include <osquery/hash.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

namespace pt = boost::property_tree;
typedef std::map<std::string, std::vector<std::string> > EventFileMap_t;

namespace osquery {

CLI_FLAG(string, config_plugin, "filesystem", "Config plugin name");

// This lock is used to protect the entirety of the OSqueryConfig struct
// Is should be used when ever accessing the structs members, reading or
// writing.
static boost::shared_mutex rw_lock;

Status Config::load() {
  if (!Registry::exists("config", FLAGS_config_plugin)) {
    return Status(1, "Missing config plugin " + FLAGS_config_plugin);
  }

  boost::unique_lock<boost::shared_mutex> lock(rw_lock);

  // Set up the active config plugin once when the config is first loaded.
  if (!getInstance().loaded_) {
    Registry::get("config", FLAGS_config_plugin)->setUp();
    getInstance().loaded_ = true;
  }

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

Status Config::genConfig(std::string& conf) {
  if (!Registry::exists("config", FLAGS_config_plugin)) {
    LOG(ERROR) << "Config retriever " << FLAGS_config_plugin << " not found";
    return Status(1, "Config retriever not found");
  }

  PluginResponse response;
  auto status = Registry::call(
      "config", FLAGS_config_plugin, {{"action", "genConfig"}}, response);

  if (!status.ok()) {
    return status;
  }

  conf = response[0].at("data");
  return Status(0, "OK");
}

Status Config::genConfig(OsqueryConfig& conf) {
  std::string config_string;
  auto s = genConfig(config_string);
  if (!s.ok()) {
    return s;
  }
  std::stringstream json;
  pt::ptree tree;
  try {
    json << config_string;
    pt::read_json(json, tree);
    // Parse each scheduled query from the config.
    for (const pt::ptree::value_type& v : tree.get_child("scheduledQueries")) {
      osquery::OsqueryScheduledQuery q;
      q.name = (v.second).get<std::string>("name");
      q.query = (v.second).get<std::string>("query");
      q.interval = (v.second).get<int>("interval");
      conf.scheduledQueries.push_back(q);
    }

    // Flags may be set as 'options' within the config.
    if (tree.count("options") > 0) {
      for (const pt::ptree::value_type& v : tree.get_child("options")) {
        conf.options[v.first.data()] = v.second.data();
      }
    }

    if (tree.count("additional_monitoring") > 0) {
      ReturnSetting settings = REC_LIST_FOLDERS | REC_EVENT_OPT;
      // Parse each entry in file_paths first.
      for (const pt::ptree::value_type& v :
           tree.get_child("additional_monitoring")) {
        if (v.first == "file_paths") {
          for (const pt::ptree::value_type& file_cat : v.second) {
            for (const pt::ptree::value_type& file : file_cat.second) {
              osquery::resolveFilePattern(file.second.get_value<std::string>(),
                                          conf.eventFiles[file_cat.first],
                                          settings);
            }
          }
        }
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
  } catch (const std::exception& e) {
    LOG(ERROR) << "Error parsing config JSON: " << e.what();
    return Status(1, e.what());
  }

  return Status(0, "OK");
}

std::vector<OsqueryScheduledQuery> Config::getScheduledQueries() {
  boost::shared_lock<boost::shared_mutex> lock(rw_lock);
  return getInstance().cfg_.scheduledQueries;
}

std::map<std::string, std::vector<std::string> >& Config::getWatchedFiles() {
  boost::shared_lock<boost::shared_mutex> lock(rw_lock);
  return getInstance().cfg_.eventFiles;
}

std::map<std::string, std::vector<std::string> >& Config::getYARAFiles() {
  boost::shared_lock<boost::shared_mutex> lock(rw_lock);
  return getInstance().cfg_.yaraFiles;
}

Status Config::getMD5(std::string& hash_string) {
  std::string config_string;
  auto s = genConfig(config_string);
  if (!s.ok()) {
    return s;
  }

  hash_string = osquery::hashFromBuffer(
      HASH_TYPE_MD5, (void*)config_string.c_str(), config_string.length());

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
    auto config_data = genConfig();
    response.push_back({{"data", config_data.second}});
    return config_data.first;
  }
  return Status(1, "Config plugin action unknown: " + request.at("action"));
}
}
