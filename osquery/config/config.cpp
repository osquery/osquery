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

#include "osquery/core/watcher.h"

namespace pt = boost::property_tree;
typedef std::map<std::string, std::vector<std::string> > EventFileMap_t;

namespace osquery {

FLAG(string, config_plugin, "filesystem", "Config type (plugin)");

// This lock is used to protect the entirety of the OSqueryConfig struct
// Is should be used when ever accessing the structs members, reading or
// writing.
static boost::shared_mutex rw_lock;

Status Config::load() {
  boost::unique_lock<boost::shared_mutex> lock(rw_lock);
  OsqueryConfig conf;

  auto s = Config::genConfig(conf);
  if (!s.ok()) {
    return Status(1, "Cannot generate config");
  }

  // Override default arguments with flag options from config.
  for (const auto& option : conf.options) {
    if (Flag::isDefault(option.first)) {
      // Only override if option was NOT given as an argument.
      Flag::updateValue(option.first, option.second);
      if (!osquery::isOsqueryWorker()) {
        VLOG(1) << "Setting flag option: " << option.first << "="
                << option.second;
      }
    }
  }
  cfg_ = conf;
  return Status(0, "OK");
}

Status Config::genConfig(std::vector<std::string>& conf) {
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

  if (response.size() > 0) {
    for (const auto& it : response[0]) {
      conf.push_back(it.second);
    }
  }
  return Status(0, "OK");
}

Status Config::genConfig(OsqueryConfig& conf) {
  std::vector<std::string> config_files;
  auto s = genConfig(config_files);
  if (!s.ok()) {
    return s;
  }
  std::stringstream json;
  pt::ptree tree, scheduled_queries, options, additional_monitoring;

  for (const auto& conf_file : config_files) {
    std::stringstream json;
    json << conf_file;

    pt::read_json(json, tree);
    if (tree.count("scheduledQueries") > 0) {
      for (const pt::ptree::value_type& v :
           tree.get_child("scheduledQueries")) {
        osquery::OsqueryScheduledQuery q;
        pt::ptree child;

        q.name = (v.second).get<std::string>("name");
        q.query = (v.second).get<std::string>("query");
        q.interval = (v.second).get<int>("interval");

        child.put("name", (v.second).get<std::string>("name"));
        child.put("query", (v.second).get<std::string>("query"));
        child.put("interval", (v.second).get<int>("interval"));

        scheduled_queries.add_child("", child);
        conf.scheduledQueries.push_back(q);
      }
    }

    if (tree.count("additional_monitoring") > 0) {
      ReturnSetting settings = REC_LIST_FOLDERS | REC_EVENT_OPT;
      for (const pt::ptree::value_type& v :
           tree.get_child("additional_monitoring")) {
        additional_monitoring.add_child(v.first, v.second);
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
    }
    // Flags may be set as 'options' within the config.
    if (tree.count("options") > 0) {
      for (const pt::ptree::value_type& v : tree.get_child("options")) {
        conf.options[v.first.data()] = v.second.data();
        options.add_child(v.first, v.second);
      }
    }
  }
  conf.all_data.add_child("scheduledQueries", scheduled_queries);
  conf.all_data.add_child("options", options);
  conf.all_data.add_child("additional_monitoring", additional_monitoring);

  std::stringstream out;
  write_json(out, conf.all_data);
  VLOG(1) << "The merged configuration:\n" << out.str();
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
    std::map<std::string, std::string> returned_config;
    auto stat = genConfig(returned_config);
    response.push_back(returned_config);
    return stat;
  }
  return Status(1, "Config plugin action unknown: " + request.at("action"));
}
}
