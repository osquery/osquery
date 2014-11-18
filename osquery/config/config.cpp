// Copyright 2004-present Facebook. All Rights Reserved.

#include <algorithm>
#include <future>
#include <sstream>
#include <string>
#include <vector>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/thread/shared_mutex.hpp>

#include <glog/logging.h>

#include "osquery/config.h"
#include "osquery/config/plugin.h"
#include "osquery/flags.h"
#include "osquery/status.h"

using osquery::Status;

namespace pt = boost::property_tree;

namespace osquery {

DEFINE_osquery_flag(string,
                    config_retriever,
                    "filesystem",
                    "The config mechanism to retrieve config content via.");

/// The percent to splay config times by
DEFINE_osquery_flag(int32,
                    schedule_splay_percent,
                    10,
                    "The percent to splay config times by");

boost::shared_mutex rw_lock;

std::shared_ptr<Config> Config::getInstance() {
  static std::shared_ptr<Config> config = std::shared_ptr<Config>(new Config());
  return config;
}

Config::Config() {
  boost::unique_lock<boost::shared_mutex> lock(rw_lock);
  OsqueryConfig conf;
  auto s = Config::genConfig(conf);
  if (!s.ok()) {
    LOG(ERROR) << "error retrieving config: " << s.toString();
  } else {
    for (auto& q : conf.scheduledQueries) {
      auto old_interval = q.interval;
      auto new_interval =
          splayValue(old_interval, FLAGS_schedule_splay_percent);
      LOG(INFO) << "Changing the interval for " << q.name << " from  "
                << old_interval << " to " << new_interval;
      q.interval = new_interval;
    }
  }
  cfg_ = conf;
}

Status Config::genConfig(OsqueryConfig& conf) {
  std::stringstream json;
  pt::ptree tree;

  if (REGISTERED_CONFIG_PLUGINS.find(FLAGS_config_retriever) ==
      REGISTERED_CONFIG_PLUGINS.end()) {
    LOG(ERROR) << "Config retriever " << FLAGS_config_retriever << " not found";
    return Status(1, "Config retriever not found");
  }
  auto config_data =
      REGISTERED_CONFIG_PLUGINS.at(FLAGS_config_retriever)->genConfig();
  if (!config_data.first.ok()) {
    return config_data.first;
  }
  json << config_data.second;
  pt::read_json(json, tree);

  try {
    for (const pt::ptree::value_type& v : tree.get_child("scheduledQueries")) {
      OsqueryScheduledQuery q;
      q.name = (v.second).get<std::string>("name");
      q.query = (v.second).get<std::string>("query");
      q.interval = (v.second).get<int>("interval");
      conf.scheduledQueries.push_back(q);
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

int Config::splayValue(int original, int splayPercent) {
  if (splayPercent <= 0 || splayPercent > 100) {
    return original;
  }

  float percent_to_modify_by = (float)splayPercent / 100;
  int possible_difference = original * percent_to_modify_by;
  int max_value = original + possible_difference;
  int min_value = original - possible_difference;

  if (max_value == min_value) {
    return max_value;
  }

  return (rand() % (max_value - min_value)) + min_value;
}
}
