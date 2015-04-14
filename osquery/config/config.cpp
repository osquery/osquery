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
#include <random>
#include <sstream>

#include <osquery/config.h>
#include <osquery/flags.h>
#include <osquery/hash.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry.h>

namespace pt = boost::property_tree;

typedef pt::ptree::value_type tree_node;
typedef std::map<std::string, std::vector<std::string> > EventFileMap_t;

namespace osquery {

CLI_FLAG(string, config_plugin, "filesystem", "Config plugin name");

FLAG(int32, schedule_splay_percent, 10, "Percent to splay config times");

Status Config::load() {
  auto& config_plugin = Registry::getActive("config");
  if (!Registry::exists("config", config_plugin)) {
    return Status(1, "Missing config plugin " + config_plugin);
  }

  return genConfig();
}

Status Config::update(const std::map<std::string, std::string>& config) {
  // A config plugin may call update from an extension. This will update
  // the config instance within the extension process and the update must be
  // reflected in the core.
  if (Registry::external()) {
    for (const auto& source : config) {
      PluginRequest request = {
          {"action", "update"},
          {"source", source.first},
          {"data", source.second},
      };
      // A "update" registry item within core should call the core's update
      // method. The config plugin call action handling must also know to
      // update.
      Registry::call("config", "update", request);
    }
  }

  // Request a unique write lock when updating config.
  boost::unique_lock<boost::shared_mutex> unique_lock(getInstance().mutex_);

  ConfigData conf;
  for (const auto& source : config) {
    if (Registry::external()) {
      VLOG(1) << "Updating extension config source: " << source.first;
    } else {
      VLOG(1) << "Updating config source: " << source.first;
    }
    getInstance().raw_[source.first] = source.second;
  }

  // Now merge all sources together.
  for (const auto& source : getInstance().raw_) {
    mergeConfig(source.second, conf);
  }

  // Call each parser with the optionally-empty, requested, top level keys.
  for (const auto& plugin : Registry::all("config_parser")) {
    auto parser = std::static_pointer_cast<ConfigParserPlugin>(plugin.second);
    if (parser == nullptr || parser.get() == nullptr) {
      continue;
    }

    // For each key requested by the parser, add a property tree reference.
    std::map<std::string, ConfigTree> parser_config;
    for (const auto& key : parser->keys()) {
      if (conf.all_data.count(key) > 0) {
        parser_config[key] = conf.all_data.get_child(key);
      } else {
        parser_config[key] = pt::ptree();
      }
    }
    parser->update(parser_config);
  }

  getInstance().data_ = conf;
  return Status(0, "OK");
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

// inline void mergeScheduledQuery(const tree_node& node, ConfigData& conf) {
inline void mergeScheduledQuery(const std::string& name,
                                const tree_node& node,
                                ConfigData& conf) {
  // Read tree/JSON into a query structure.
  ScheduledQuery query;
  query.query = node.second.get<std::string>("query", "");
  query.interval = node.second.get<int>("interval", 0);

  // Check if this query exists, if so, check if it was changed.
  if (conf.schedule.count(name) > 0) {
    if (query == conf.schedule.at(name)) {
      return;
    }
  }

  // This is a new or updated scheduled query, update the splay.
  query.splayed_interval =
      splayValue(query.interval, FLAGS_schedule_splay_percent);
  // Update the schedule map and replace the all_data node record.
  conf.schedule[name] = query;
  if (conf.all_data.count("schedule") > 0) {
    conf.all_data.get_child("schedule").erase(name);
  }
  conf.all_data.add_child("schedule." + name, node.second);
}

inline void mergeExtraKey(const std::string& name,
                          const tree_node& node,
                          ConfigData& conf) {
  // Automatically merge extra list/dict top level keys.
  for (const auto& subitem : node.second) {
    if (node.second.count("") == 0 && conf.all_data.count(name) > 0) {
      conf.all_data.get_child(name).erase(subitem.first);
    }
    conf.all_data.add_child(name + "." + subitem.first, subitem.second);
  }
}

inline void mergeFilePath(const std::string& name,
                          const tree_node& node,
                          ConfigData& conf) {
  for (const auto& path : node.second) {
    resolveFilePattern(path.second.data(),
                       conf.files[node.first],
                       REC_LIST_FOLDERS | REC_EVENT_OPT);
  }
  conf.all_data.add_child(name + "." + node.first, node.second);
}

void Config::mergeConfig(const std::string& source, ConfigData& conf) {
  std::stringstream json_data;
  json_data << source;

  pt::ptree tree;
  try {
    pt::read_json(json_data, tree);
  } catch (const pt::ptree_error& e) {
    VLOG(1) << "Error parsing config JSON: " << e.what();
    return;
  }

  if (tree.count("additional_monitoring") > 0) {
    LOG(INFO) << RLOG(903) << "config 'additional_monitoring' is deprecated";
    for (const auto& node : tree.get_child("additional_monitoring")) {
      tree.add_child(node.first, node.second);
    }
    tree.erase("additional_monitoring");
  }

  for (const auto& item : tree) {
    // Iterate over each top-level configuration key.
    auto key = std::string(item.first.data());
    if (key == "scheduledQueries") {
      LOG(INFO) << RLOG(903) << "config 'scheduledQueries' is deprecated";
      for (const auto& node : item.second) {
        auto query_name = node.second.get<std::string>("name", "");
        mergeScheduledQuery(query_name, node, conf);
      }
    } else if (key == "schedule") {
      for (const auto& node : item.second) {
        mergeScheduledQuery(node.first.data(), node, conf);
      }
    } else if (key == "options") {
      for (const auto& option : item.second) {
        mergeOption(option, conf);
      }
    } else if (key == "file_paths") {
      for (const auto& category : item.second) {
        mergeFilePath(key, category, conf);
      }
    } else {
      mergeExtraKey(key, item, conf);
    }
  }
}

const pt::ptree& Config::getParsedData(const std::string& key) {
  if (!Registry::exists("config_parser", key)) {
    return getInstance().empty_data_;
  }

  const auto& item = Registry::get("config_parser", key);
  auto parser = std::static_pointer_cast<ConfigParserPlugin>(item);
  if (parser == nullptr || parser.get() == nullptr) {
    return getInstance().empty_data_;
  }

  return parser->data_;
}

Status Config::getMD5(std::string& hash_string) {
  // Request an accessor to our own config, outside of an update.
  ConfigDataInstance config;

  std::stringstream out;
  pt::write_json(out, config.data());

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
  } else if (request.at("action") == "update") {
    if (request.count("source") == 0 || request.count("data") == 0) {
      return Status(1, "Missing source or data");
    }
    return Config::update({{request.at("source"), request.at("data")}});
  }
  return Status(1, "Config plugin action unknown: " + request.at("action"));
}

Status ConfigParserPlugin::setUp() {
  for (const auto& key : keys()) {
    data_.put(key, "");
  }
  return Status(0, "OK");
}

int splayValue(int original, int splayPercent) {
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

  std::default_random_engine generator;
  std::uniform_int_distribution<int> distribution(min_value, max_value);
  return distribution(generator);
}
}
