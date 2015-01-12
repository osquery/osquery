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

#include <glog/logging.h>

#include <osquery/config.h>
#include <osquery/config/plugin.h>
#include <osquery/flags.h>

#include "osquery/core/md5.h"

namespace pt = boost::property_tree;

namespace osquery {

DEFINE_osquery_flag(string,
                    config_retriever,
                    "filesystem",
                    "Config type (plugin).");

boost::shared_mutex rw_lock;

std::shared_ptr<Config> Config::getInstance() {
  static std::shared_ptr<Config> config = std::shared_ptr<Config>(new Config());
  return config;
}

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
      VLOG(1) << "Setting flag option: " << option.first << "="
              << option.second;
    }
  }

  cfg_ = conf;
  return Status(0, "OK");
}

Status Config::genConfig(std::string& conf) {
  if (REGISTERED_CONFIG_PLUGINS.find(FLAGS_config_retriever) ==
      REGISTERED_CONFIG_PLUGINS.end()) {
    LOG(ERROR) << "Config retriever " << FLAGS_config_retriever << " not found";
    return Status(1, "Config retriever not found");
  }

  try {
    auto config_data =
        REGISTERED_CONFIG_PLUGINS.at(FLAGS_config_retriever)->genConfig();
    if (!config_data.first.ok()) {
      return config_data.first;
    }
    conf = config_data.second;
  } catch (std::exception& e) {
    LOG(ERROR) << "Could not load ConfigPlugin " << FLAGS_config_retriever
               << ": " << e.what();
    return Status(1, "Could not load config plugin");
  }

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
      OsqueryScheduledQuery q;
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
  } catch (const std::exception& e) {
    LOG(ERROR) << "Error parsing config JSON: " << e.what();
    return Status(1, e.what());
  }

  return Status(0, "OK");
}

std::vector<OsqueryScheduledQuery> Config::getScheduledQueries() {
  boost::shared_lock<boost::shared_mutex> lock(rw_lock);
  return cfg_.scheduledQueries;
}

Status Config::getMD5(std::string& hashString) {
  std::string config_string;
  auto s = genConfig(config_string);
  if (!s.ok()) {
    return s;
  }

  osquery::md5::MD5 digest;
  hashString = std::string(digest.digestString(config_string.c_str()));

  return Status(0, "OK");
}
}
