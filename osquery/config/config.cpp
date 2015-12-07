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

#include <boost/algorithm/string/trim.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/thread/shared_mutex.hpp>

#include <osquery/config.h>
#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/hash.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace pt = boost::property_tree;

namespace osquery {

/// The config plugin must be known before reading options.
CLI_FLAG(string, config_plugin, "filesystem", "Config plugin name");

CLI_FLAG(bool,
         config_check,
         false,
         "Check the format of an osquery config and exit");

CLI_FLAG(bool, config_dump, false, "Dump the contents of the configuration");

DECLARE_string(config_plugin);
DECLARE_string(pack_delimiter);

/**
 * @brief The backing store key name for the executing query.
 *
 * The config maintains schedule statistics and tracks failed executions.
 * On process or worker resume an initializer or config may check if the
 * resume was the result of a failure during an executing query.
 */
const std::string kExecutingQuery = "executing_query";
const std::string kFailedQueries = "failed_queries";

// The config may be accessed and updated asynchronously; use mutexes.
boost::shared_mutex config_schedule_mutex_;
boost::shared_mutex config_performance_mutex_;
boost::shared_mutex config_files_mutex_;
boost::shared_mutex config_hash_mutex_;
boost::shared_mutex config_valid_mutex_;

void restoreScheduleBlacklist(std::map<std::string, size_t>& blacklist) {
  std::string content;
  getDatabaseValue(kPersistentSettings, kFailedQueries, content);
  auto blacklist_pairs = osquery::split(content, ":");
  if (blacklist_pairs.size() == 0 || blacklist_pairs.size() % 2 != 0) {
    // Nothing in the blacklist, or malformed data.
    return;
  }

  size_t current_time = getUnixTime();
  for (size_t i = 0; i < blacklist_pairs.size() / 2; i++) {
    // Fill in a mapping of query name to time the blacklist expires.
    long int expire = 0;
    safeStrtol(blacklist_pairs[(i * 2) + 1], 10, expire);
    if (expire > 0 && current_time < (size_t)expire) {
      blacklist[blacklist_pairs[(i * 2)]] = (size_t)expire;
    }
  }
}

void saveScheduleBlacklist(const std::map<std::string, size_t>& blacklist) {
  std::string content;
  for (const auto& query : blacklist) {
    if (!content.empty()) {
      content += ":";
    }
    content += query.first + ":" + std::to_string(query.second);
  }
  setDatabaseValue(kPersistentSettings, kFailedQueries, content);
}

Schedule::Schedule() {
  if (Registry::external()) {
    // Extensions should not restore or save schedule details.
    return;
  }
  // Parse the schedule's query blacklist from backing storage.
  restoreScheduleBlacklist(blacklist_);

  // Check if any queries were executing when the tool last stopped.
  getDatabaseValue(kPersistentSettings, kExecutingQuery, failed_query_);
  if (!failed_query_.empty()) {
    LOG(WARNING) << "Scheduled query may have failed: " << failed_query_;
    setDatabaseValue(kPersistentSettings, kExecutingQuery, "");
    // Add this query name to the blacklist and save the blacklist.
    blacklist_[failed_query_] = getUnixTime() + 86400;
    saveScheduleBlacklist(blacklist_);
  }
}

void Config::addPack(const std::string& name,
                     const std::string& source,
                     const pt::ptree& tree) {
  WriteLock wlock(config_schedule_mutex_);
  try {
    schedule_.add(Pack(name, source, tree));
  } catch (const std::exception& e) {
    LOG(WARNING) << "Error adding pack: " << name << ": " << e.what();
  }
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
      // The query name may be synthetic.
      if (pack.getName() != "main" && pack.getName() != "legacy_main") {
        name = "pack" + FLAGS_pack_delimiter + pack.getName() +
               FLAGS_pack_delimiter + it.first;
      }
      // They query may have failed and been added to the schedule's blacklist.
      if (schedule_.blacklist_.count(name) > 0) {
        auto blacklisted_query = schedule_.blacklist_.find(name);
        if (getUnixTime() > blacklisted_query->second) {
          // The blacklisted query passed the expiration time (remove).
          schedule_.blacklist_.erase(blacklisted_query);
          saveScheduleBlacklist(schedule_.blacklist_);
        } else {
          // The query is still blacklisted.
          continue;
        }
      }
      // Call the predicate.
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

Status Config::load() {
  valid_ = false;
  auto& config_plugin = Registry::getActive("config");
  if (!Registry::exists("config", config_plugin)) {
    return Status(1, "Missing config plugin " + config_plugin);
  }

  PluginResponse response;
  auto status = Registry::call("config", {{"action", "genConfig"}}, response);
  if (!status.ok()) {
    return status;
  }

  // if there was a response, parse it and update internal state
  valid_ = true;
  if (response.size() > 0) {
    if (FLAGS_config_dump) {
      // If config checking is enabled, debug-write the raw config data.
      for (const auto& content : response[0]) {
        fprintf(stdout,
                "{\"%s\": %s}\n",
                content.first.c_str(),
                content.second.c_str());
      }
      ::exit(EXIT_SUCCESS);
    }
    return update(response[0]);
  }

  return Status(0, "OK");
}

/**
 * @brief Boost's 1.59 property tree based JSON parser does not accept comments.
 *
 * For semi-compatibility with existing configurations we will attempt to strip
 * hash and C++ style comments. It is OK for the config update to be latent
 * as it is a single event. But some configuration plugins may update running
 * configurations.
 */
inline void stripConfigComments(std::string& json) {
  std::string sink;
  for (auto& line : osquery::split(json, "\n")) {
    boost::trim(line);
    if (line.size() > 0 && line[0] == '#') {
      continue;
    }
    if (line.size() > 1 && line[0] == '/' && line[1] == '/') {
      continue;
    }
    sink += line + '\n';
  }
  json = sink;
}

Status Config::updateSource(const std::string& name, const std::string& json) {
  // Compute a 'synthesized' hash using the content before it is parsed.
  hashSource(name, json);

  // load the config (source.second) into a pt::ptree
  pt::ptree tree;
  try {
    auto clone = json;
    stripConfigComments(clone);
    std::stringstream json_stream;
    json_stream << clone;
    pt::read_json(json_stream, tree);
  } catch (const pt::json_parser::json_parser_error& e) {
    return Status(1, "Error parsing the config JSON");
  }

  // extract the "schedule" key and store it as the main pack
  if (tree.count("schedule") > 0 && !Registry::external()) {
    auto& schedule = tree.get_child("schedule");
    pt::ptree main_pack;
    main_pack.add_child("queries", schedule);
    addPack("main", name, main_pack);
  }

  if (tree.count("scheduledQueries") > 0 && !Registry::external()) {
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
    addPack("legacy_main", name, legacy_pack);
  }

  // extract the "packs" key into additional pack objects
  if (tree.count("packs") > 0 && !Registry::external()) {
    auto& packs = tree.get_child("packs");
    for (const auto& pack : packs) {
      auto value = packs.get<std::string>(pack.first, "");
      if (value.empty()) {
        addPack(pack.first, name, pack.second);
      } else {
        PluginResponse response;
        PluginRequest request = {
            {"action", "genPack"}, {"name", pack.first}, {"value", value}};
        Registry::call("config", request, response);

        if (response.size() == 0 || response[0].count(pack.first) == 0) {
          continue;
        }

        try {
          pt::ptree pack_tree;
          std::stringstream pack_stream;
          pack_stream << response[0][pack.first];
          pt::read_json(pack_stream, pack_tree);
          addPack(pack.first, name, pack_tree);
        } catch (const pt::json_parser::json_parser_error& e) {
          LOG(WARNING) << "Error parsing the pack JSON: " << pack.first;
        }
      }
    }
  }

  for (const auto& plugin : Registry::all("config_parser")) {
    std::shared_ptr<ConfigParserPlugin> parser = nullptr;
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

  // Iterate though each source and overwrite config data.
  // This will add/overwrite pack data, append to the schedule, change watched
  // files, set options, etc.
  // Before this occurs, take an opportunity to purge stale state.
  purge();

  for (const auto& source : config) {
    auto status = updateSource(source.first, source.second);
    if (!status.ok()) {
      return status;
    }
  }

  return Status(0, "OK");
}

void Config::purge() {
  // The first use of purge is removing expired query results.
  std::vector<std::string> saved_queries;
  scanDatabaseKeys(kQueries, saved_queries);

  const auto& schedule = this->schedule_;
  auto queryExists = [&schedule](const std::string& query_name) {
    for (const auto& pack : schedule.packs_) {
      const auto& pack_queries = pack.getSchedule();
      if (pack_queries.count(query_name)) {
        return true;
      }
    }
    return false;
  };

  ReadLock rlock(config_schedule_mutex_);
  // Iterate over each result set in the database.
  for (const auto& saved_query : saved_queries) {
    if (queryExists(saved_query)) {
      continue;
    }

    std::string content;
    getDatabaseValue(kPersistentSettings, "timestamp." + saved_query, content);
    if (content.empty()) {
      // No timestamp is set for this query, perhaps this is the first time
      // query results expiration is applied.
      setDatabaseValue(kPersistentSettings,
                       "timestamp." + saved_query,
                       std::to_string(getUnixTime()));
      continue;
    }

    // Parse the timestamp and compare.
    size_t last_executed = 0;
    try {
      last_executed = boost::lexical_cast<size_t>(content);
    } catch (const boost::bad_lexical_cast& e) {
      // Erase the timestamp as is it potentially corrupt.
      deleteDatabaseValue(kPersistentSettings, "timestamp." + saved_query);
      continue;
    }

    if (last_executed < getUnixTime() - 592200) {
      // Query has not run in the last week, expire results and interval.
      deleteDatabaseValue(kQueries, saved_query);
      deleteDatabaseValue(kPersistentSettings, "interval." + saved_query);
      deleteDatabaseValue(kPersistentSettings, "timestamp." + saved_query);
      VLOG(1) << "Expiring results for scheduled query: " << saved_query;
    }
  }
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
  BIGINT_LITERAL diff = 0;
  if (!r1.at("user_time").empty() && !r0.at("user_time").empty()) {
    diff = AS_LITERAL(BIGINT_LITERAL, r1.at("user_time")) -
           AS_LITERAL(BIGINT_LITERAL, r0.at("user_time"));
    if (diff > 0) {
      query.user_time += diff;
    }
  }

  if (!r1.at("system_time").empty() && !r0.at("system_time").empty()) {
    diff = AS_LITERAL(BIGINT_LITERAL, r1.at("system_time")) -
           AS_LITERAL(BIGINT_LITERAL, r0.at("system_time"));
    if (diff > 0) {
      query.system_time += diff;
    }
  }

  if (!r1.at("resident_size").empty() && !r0.at("resident_size").empty()) {
    diff = AS_LITERAL(BIGINT_LITERAL, r1.at("resident_size")) -
           AS_LITERAL(BIGINT_LITERAL, r0.at("resident_size"));
    if (diff > 0) {
      // Memory is stored as an average of RSS changes between query executions.
      query.average_memory = (query.average_memory * query.executions) + diff;
      query.average_memory = (query.average_memory / (query.executions + 1));
    }
  }

  query.wall_time += delay;
  query.output_size += size;
  query.executions += 1;
  query.last_executed = getUnixTime();

  // Clear the executing query (remove the dirty bit).
  setDatabaseValue(kPersistentSettings, kExecutingQuery, "");
}

void Config::recordQueryStart(const std::string& name) {
  // There should only ever be a single executing query in the schedule.
  setDatabaseValue(kPersistentSettings, kExecutingQuery, name);
  // Store the time this query name last executed for later results eviction.
  // When configuration updates occur the previous schedule is searched for
  // 'stale' query names, aka those that have week-old or longer last execute
  // timestamps. Offending queries have their database results purged.
  setDatabaseValue(
      kPersistentSettings, "timestamp." + name, std::to_string(getUnixTime()));
}

void Config::getPerformanceStats(
    const std::string& name,
    std::function<void(const QueryPerformance& query)> predicate) {
  if (performance_.count(name) > 0) {
    ReadLock rlock(config_performance_mutex_);
    predicate(performance_.at(name));
  }
}

void Config::hashSource(const std::string& source, const std::string& content) {
  WriteLock wlock(config_hash_mutex_);
  hash_[source] =
      hashFromBuffer(HASH_TYPE_MD5, &(content.c_str())[0], content.size());
}

Status Config::getMD5(std::string& hash) {
  if (!valid_) {
    return Status(1, "Current config is not valid");
  }

  ReadLock rlock(config_hash_mutex_);
  std::vector<char> buffer;
  buffer.reserve(hash_.size() * 32);
  auto add = [&buffer](const std::string& text) {
    for (const auto& c : text) {
      buffer.push_back(c);
    }
  };
  for (const auto& it : hash_) {
    add(it.second);
  }

  hash = hashFromBuffer(HASH_TYPE_MD5, &buffer[0], buffer.size());
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
}
