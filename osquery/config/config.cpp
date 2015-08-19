/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <chrono>
#include <mutex>
#include <random>
#include <sstream>

#include <osquery/config.h>
#include <osquery/flags.h>
#include <osquery/hash.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/tables.h>

namespace pt = boost::property_tree;

namespace osquery {

/// The config plugin must be known before reading options.
CLI_FLAG(string, config_plugin, "filesystem", "Config plugin name");

FLAG(int32, schedule_splay_percent, 10, "Percent to splay config times");

boost::shared_mutex config_schedule_mutex_;
boost::shared_mutex config_performance_mutex_;
boost::shared_mutex config_files_mutex_;
boost::shared_mutex config_hash_mutex_;

void Config::addPack(const Pack& pack) {
  WriteLock wlock(config_schedule_mutex_);
  return schedule_.add(pack);
}

void Config::removePack(const std::string& pack) {
  WriteLock wlock(config_schedule_mutex_);
  return schedule_.remove(pack);
}

void Config::addFile(const std::string& category, const std::string& path) {
  WriteLock wlock(config_files_mutex_);
  files_[category].push_back(path);
}

void Config::scheduledQueries(std::function<
    void(const std::string& name, const ScheduledQuery& query)> predicate) {
  ReadLock rlock(config_schedule_mutex_);
  for (Pack& pack : schedule_) {
    for (const auto& it : pack.getSchedule()) {
      std::string name = it.first;
      if (pack.getName() != "main" && pack.getName() != "legacy_main") {
        name = "pack_" + pack.getName() + "_" + it.first;
      }
      predicate(name, it.second);
    }
  }
}

void Config::packs(std::function<void(Pack& pack)> predicate) {
  ReadLock rlock(config_schedule_mutex_);
  for (Pack& pack : schedule_.packs_) {
    predicate(pack);
  }
}

void Config::clearSchedule() {
  WriteLock wlock(config_schedule_mutex_);
  schedule_ = Schedule();
}

void Config::clearHash() {
  WriteLock wlock(config_hash_mutex_);
  std::string().swap(hash_);
}

void Config::clearFiles() {
  WriteLock wlock(config_files_mutex_);
  files_.erase(files_.begin(), files_.end());
}

Status Config::load() {
  auto& config_plugin = Registry::getActive("config");
  if (!Registry::exists("config", config_plugin)) {
    return Status(1, "Missing config plugin " + config_plugin);
  }

  PluginResponse response;
  auto status = Registry::call("config", {{"action", "genConfig"}}, response);
  if (!status.ok()) {
    return status;
  }

  // clear existing state
  clearSchedule();
  clearHash();
  clearFiles();

  // if there was a response, parse it and update internal state
  if (response.size() > 0) {
    return update(response[0]);
  }

  return Status(0, "OK");
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

  for (const auto& source : config) {
    // load the config (source.second) into a pt::ptree
    std::stringstream json;
    json << source.second;
    pt::ptree tree;
    try {
      pt::read_json(json, tree);
    } catch (const pt::json_parser::json_parser_error& e) {
      return Status(1, "Error parsing the config JSON. Check the syntax.");
    }

    // extract the "schedule" key and store it as the main pack
    if (tree.count("schedule") > 0) {
      auto& schedule = tree.get_child("schedule");
      pt::ptree main_pack;
      main_pack.add_child("queries", schedule);
      addPack(Pack("main", source.first, main_pack));
    }

    if (tree.count("scheduledQueries") > 0) {
      auto& scheduled_queries = tree.get_child("scheduledQueries");
      pt::ptree queries;
      for (const std::pair<std::string, pt::ptree>& query : scheduled_queries) {
        auto query_name = query.second.get<std::string>("name", "");
        if (query_name.empty()) {
          return Status(1, "Error getting name from legacy scheduled query");
        }
        queries.add_child(query_name, query.second);
      }
      pt::ptree legacy_pack;
      legacy_pack.add_child("queries", queries);
      addPack(Pack("legacy_main", source.first, legacy_pack));
    }

    // extract the "packs" key into additional pack objects
    if (tree.count("packs") > 0) {
      auto& packs = tree.get_child("packs");
      for (const auto& pack : packs) {
        auto value = packs.get<std::string>(pack.first, "");
        if (value.empty()) {
          addPack(Pack(pack.first, source.first, pack.second));
        } else {
          PluginResponse response;
          auto status = Registry::call(
              "config",
              {{"action", "genPack"}, {"name", pack.first}, {"value", value}},
              response);
          if (!status.ok()) {
            return status;
          }

          if (response.size() > 0) {
            try {
              addPack(Pack(pack.first, source.first, response[0][pack.first]));
            } catch (const std::exception& e) {
              return Status(1,
                            "Error accessing pack plugin response: " +
                                std::string(e.what()));
            }
          }
        }
      }
    }

    for (const auto& plugin : Registry::all("config_parser")) {
      std::shared_ptr<ConfigParserPlugin> parser;
      try {
        parser = std::dynamic_pointer_cast<ConfigParserPlugin>(plugin.second);
      } catch (const std::bad_cast& e) {
        LOG(ERROR) << "Error casting config parser plugin: " << plugin.first;
      }
      if (parser == nullptr || parser.get() == nullptr) {
        continue;
      }

      // For each key requested by the parser, add a property tree reference.
      std::map<std::string, pt::ptree> parser_config;
      for (const auto& key : parser->keys()) {
        if (tree.count(key) > 0) {
          parser_config[key] = tree.get_child(key);
        } else {
          parser_config[key] = pt::ptree();
        }
      }

      // The config parser plugin will receive a copy of each property tree for
      // each top-level-config key. The parser may choose to update the config's
      // internal state
      parser->update(parser_config);
    }
  }

  return Status(0, "OK");
}

void Config::recordQueryPerformance(const std::string& name,
                                    size_t delay,
                                    size_t size,
                                    const Row& r0,
                                    const Row& r1) {
  WriteLock wlock(config_performance_mutex_);
  if (performance_.count(name) == 0) {
    performance_[name] = QueryPerformance();
  }

  // Grab access to the non-const schedule item.
  auto& query = performance_.at(name);
  auto diff = AS_LITERAL(BIGINT_LITERAL, r1.at("user_time")) -
              AS_LITERAL(BIGINT_LITERAL, r0.at("user_time"));
  if (diff > 0) {
    query.user_time += diff;
  }

  diff = AS_LITERAL(BIGINT_LITERAL, r1.at("system_time")) -
         AS_LITERAL(BIGINT_LITERAL, r0.at("system_time"));
  if (diff > 0) {
    query.system_time += diff;
  }

  diff = AS_LITERAL(BIGINT_LITERAL, r1.at("resident_size")) -
         AS_LITERAL(BIGINT_LITERAL, r0.at("resident_size"));
  if (diff > 0) {
    // Memory is stored as an average of RSS changes between query executions.
    query.average_memory = (query.average_memory * query.executions) + diff;
    query.average_memory = (query.average_memory / (query.executions + 1));
  }

  query.wall_time += delay;
  query.output_size += size;
  query.executions += 1;
}

void Config::getPerformanceStats(
    const std::string& name,
    std::function<void(const QueryPerformance& query)> predicate) {
  if (performance_.count(name) > 0) {
    ReadLock rlock(config_performance_mutex_);
    predicate(performance_.at(name));
  }
}

Status Config::getMD5(std::string& hash) {
  if (hash_.empty()) {
    std::vector<char> buffer;
    auto add = [&buffer](const std::string& text) {
      for (const auto& c : text) {
        buffer.push_back(c);
      }
    };
    scheduledQueries(
        [&add, &buffer](const std::string& name, const ScheduledQuery& query) {
          add(name);
          add(query.query);
          add(std::to_string(query.interval));
          for (const auto& it : query.options) {
            add(it.first);
            add(it.second ? "true" : "false");
          }
        });

    auto parsers = Registry::all("config_parser");
    for (const auto& parser : parsers) {
      add(parser.first);
      try {
        if (parser.second == nullptr || parser.second.get() == nullptr) {
          continue;
        }
        auto plugin =
            std::static_pointer_cast<ConfigParserPlugin>(parser.second);
        if (plugin == nullptr || plugin.get() == nullptr) {
          continue;
        }
        std::stringstream ss;
        pt::write_json(ss, plugin->getData());
        add(ss.str());
      } catch (const std::bad_cast& e) {
        LOG(ERROR) << "Error casting config parser plugin: " << e.what();
      } catch (const pt::ptree_error& e) {
        LOG(ERROR)
            << "Error writing config parser content to JSON: " << e.what();
      }
    }

    std::sort(buffer.begin(), buffer.end());
    hash_ = hashFromBuffer(HASH_TYPE_MD5, &buffer[0], buffer.size());
  }

  hash = hash_;
  return Status(0, "OK");
}

const std::shared_ptr<ConfigParserPlugin> Config::getParser(
    const std::string& parser) {
  std::shared_ptr<ConfigParserPlugin> config_parser = nullptr;
  try {
    auto plugin = Registry::get("config_parser", parser);
    config_parser = std::dynamic_pointer_cast<ConfigParserPlugin>(plugin);
  } catch (const std::out_of_range& e) {
    LOG(ERROR) << "Error getting config parser plugin " << parser << ": "
               << e.what();
  } catch (const std::bad_cast& e) {
    LOG(ERROR) << "Error casting " << parser
               << " as a ConfigParserPlugin: " << e.what();
  }
  return config_parser;
}

void Config::files(
    std::function<void(const std::string& category,
                       const std::vector<std::string>& files)> predicate) {
  ReadLock rlock(config_files_mutex_);
  for (const auto& it : files_) {
    predicate(it.first, it.second);
  }
}

Status ConfigPlugin::genPack(const std::string& name,
                             const std::string& value,
                             std::string& pack) {
  return Status(1, "Not implemented");
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
  } else if (request.at("action") == "genPack") {
    if (request.count("name") == 0 || request.count("value") == 0) {
      return Status(1, "Missing name or value");
    }
    std::string pack;
    auto stat = genPack(request.at("name"), request.at("value"), pack);
    response.push_back({{request.at("name"), pack}});
    return stat;
  } else if (request.at("action") == "update") {
    if (request.count("source") == 0 || request.count("data") == 0) {
      return Status(1, "Missing source or data");
    }
    return Config::getInstance().update(
        {{request.at("source"), request.at("data")}});
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
  generator.seed(
      std::chrono::high_resolution_clock::now().time_since_epoch().count());
  std::uniform_int_distribution<int> distribution(min_value, max_value);
  return distribution(generator);
}
}
