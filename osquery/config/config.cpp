/*
 *  Copyright (c) 2014-present, Facebook, Inc.
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

#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <osquery/config.h>
#include <osquery/database.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/packs.h>
#include <osquery/registry.h>
#include <osquery/system.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/core/json.h"

namespace pt = boost::property_tree;

namespace osquery {

/**
 * @brief Config plugin registry.
 *
 * This creates an osquery registry for "config" which may implement
 * ConfigPlugin. A ConfigPlugin's call API should make use of a genConfig
 * after reading JSON data in the plugin implementation.
 */
CREATE_REGISTRY(ConfigPlugin, "config");

/**
 * @brief ConfigParser plugin registry.
 *
 * This creates an osquery registry for "config_parser" which may implement
 * ConfigParserPlugin. A ConfigParserPlugin should not export any call actions
 * but rather have a simple property tree-accessor API through Config.
 */
CREATE_LAZY_REGISTRY(ConfigParserPlugin, "config_parser");

/// The config plugin must be known before reading options.
CLI_FLAG(string, config_plugin, "filesystem", "Config plugin name");

CLI_FLAG(bool,
         config_check,
         false,
         "Check the format of an osquery config and exit");

CLI_FLAG(bool, config_dump, false, "Dump the contents of the configuration");

CLI_FLAG(uint64,
         config_refresh,
         0,
         "Optional interval in seconds to re-read configuration");

DECLARE_string(config_plugin);
DECLARE_string(pack_delimiter);
DECLARE_bool(disable_events);

/**
 * @brief The backing store key name for the executing query.
 *
 * The config maintains schedule statistics and tracks failed executions.
 * On process or worker resume an initializer or config may check if the
 * resume was the result of a failure during an executing query.
 */
const std::string kExecutingQuery{"executing_query"};
const std::string kFailedQueries{"failed_queries"};

// The config may be accessed and updated asynchronously; use mutexes.
Mutex config_hash_mutex_;
Mutex config_valid_mutex_;

/// Several config methods require enumeration via predicate lambdas.
RecursiveMutex config_schedule_mutex_;
RecursiveMutex config_files_mutex_;
RecursiveMutex config_performance_mutex_;

using PackRef = std::shared_ptr<Pack>;

/**
 * The schedule is an iterable collection of Packs. When you iterate through
 * a schedule, you only get the packs that should be running on the host that
 * you're currently operating on.
 */
class Schedule : private boost::noncopyable {
 public:
  /// Under the hood, the schedule is just a list of the Pack objects
  using container = std::list<PackRef>;

  /**
   * @brief Create a schedule maintained by the configuration.
   *
   * This will check for previously executing queries. If any query was
   * executing it is considered in a 'dirty' state and should generate logs.
   * The schedule may also choose to blacklist this query.
   */
  Schedule();

  /**
   * @brief This class' iteration function
   *
   * Our step operation will be called on each element in packs_. It is
   * responsible for determining if that element should be returned as the
   * next iterator element or skipped.
   */
  struct Step {
    bool operator()(PackRef& pack) {
      return pack->shouldPackExecute();
    }
  };

  /// Add a pack to the schedule
  void add(PackRef&& pack) {
    remove(pack->getName(), pack->getSource());
    packs_.push_back(pack);
  }

  /// Remove a pack, by name.
  void remove(const std::string& pack) {
    remove(pack, "");
  }

  /// Remove a pack by name and source.
  void remove(const std::string& pack, const std::string& source) {
    packs_.remove_if([pack, source](PackRef& p) {
      if (p->getName() == pack && (p->getSource() == source || source == "")) {
        Config::getInstance().removeFiles(source + FLAGS_pack_delimiter +
                                          p->getName());
        return true;
      }
      return false;
    });
  }

  /// Remove all packs by source.
  void removeAll(const std::string& source) {
    packs_.remove_if(([source](PackRef& p) {
      if (p->getSource() == source) {
        Config::getInstance().removeFiles(source + FLAGS_pack_delimiter +
                                          p->getName());
        return true;
      }
      return false;
    }));
  }

  /// Boost gives us a nice template for maintaining the state of the iterator
  using iterator = boost::filter_iterator<Step, container::iterator>;

  iterator begin() {
    return iterator(packs_.begin(), packs_.end());
  }

  iterator end() {
    return iterator(packs_.end(), packs_.end());
  }

  PackRef& last() {
    return packs_.back();
  }

 private:
  /// Underlying storage for the packs
  container packs_;

  /**
   * @brief The schedule will check and record previously executing queries.
   *
   * If a query is found on initialization, the name will be recorded, it is
   * possible to skip previously failed queries.
   */
  std::string failed_query_;

  /**
   * @brief List of blacklisted queries.
   *
   * A list of queries that are blacklisted from executing due to prior
   * failures. If a query caused a worker to fail it will be recorded during
   * the next execution and saved to the blacklist.
   */
  std::map<std::string, size_t> blacklist_;

 private:
  friend class Config;
};

void restoreScheduleBlacklist(std::map<std::string, size_t>& blacklist) {
  std::string content;
  getDatabaseValue(kPersistentSettings, kFailedQueries, content);
  auto blacklist_pairs = osquery::split(content, ":");
  if (blacklist_pairs.size() == 0 || blacklist_pairs.size() % 2 != 0) {
    VLOG(1) << "Failed to restore blacklist (no entries/malformed data)";
    return;
  }

  size_t current_time = getUnixTime();
  for (size_t i = 0; i < blacklist_pairs.size() / 2; i++) {
    // Fill in a mapping of query name to time the blacklist expires.
    long long expire = 0;
    safeStrtoll(blacklist_pairs[(i * 2) + 1], 10, expire);
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
  if (RegistryFactory::get().external()) {
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

Config::Config()
    : schedule_(std::make_shared<Schedule>()),
      valid_(false),
      start_time_(std::time(nullptr)) {}

void Config::addPack(const std::string& name,
                     const std::string& source,
                     const pt::ptree& tree) {
  auto addSinglePack = ([this, &source](const std::string pack_name,
                                        const pt::ptree& pack_tree) {
    RecursiveLock wlock(config_schedule_mutex_);
    try {
      schedule_->add(std::make_shared<Pack>(pack_name, source, pack_tree));
      if (schedule_->last()->shouldPackExecute()) {
        applyParsers(
            source + FLAGS_pack_delimiter + pack_name, pack_tree, true);
      }
    } catch (const std::exception& e) {
      LOG(WARNING) << "Error adding pack " << pack_name << ": " << e.what();
    }
  });

  if (name == "*") {
    // This is a multi-pack, expect the config plugin to have generated a
    // "name": {pack-content} response similar to embedded pack content
    // within the configuration.
    for (const auto& pack : tree) {
      addSinglePack(pack.first, pack.second);
    }
  } else {
    addSinglePack(name, tree);
  }
}

void Config::removePack(const std::string& pack) {
  RecursiveLock wlock(config_schedule_mutex_);
  return schedule_->remove(pack);
}

void Config::addFile(const std::string& source,
                     const std::string& category,
                     const std::string& path) {
  RecursiveLock wlock(config_files_mutex_);
  files_[source][category].push_back(path);
}

void Config::removeFiles(const std::string& source) {
  RecursiveLock wlock(config_files_mutex_);
  if (files_.count(source)) {
    FileCategories().swap(files_[source]);
  }
}

void Config::scheduledQueries(
    std::function<void(const std::string& name, const ScheduledQuery& query)>
        predicate) {
  RecursiveLock lock(config_schedule_mutex_);
  for (const PackRef& pack : *schedule_) {
    for (const auto& it : pack->getSchedule()) {
      std::string name = it.first;
      // The query name may be synthetic.
      if (pack->getName() != "main" && pack->getName() != "legacy_main") {
        name = "pack" + FLAGS_pack_delimiter + pack->getName() +
               FLAGS_pack_delimiter + it.first;
      }
      // They query may have failed and been added to the schedule's blacklist.
      if (schedule_->blacklist_.count(name) > 0) {
        auto blacklisted_query = schedule_->blacklist_.find(name);
        if (getUnixTime() > blacklisted_query->second) {
          // The blacklisted query passed the expiration time (remove).
          schedule_->blacklist_.erase(blacklisted_query);
          saveScheduleBlacklist(schedule_->blacklist_);
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

void Config::packs(std::function<void(PackRef& pack)> predicate) {
  RecursiveLock lock(config_schedule_mutex_);
  for (PackRef& pack : schedule_->packs_) {
    predicate(pack);
  }
}

Status Config::refresh() {
  PluginResponse response;
  auto status = Registry::call("config", {{"action", "genConfig"}}, response);
  if (!status.ok()) {
    loaded_ = true;
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
      // Don't force because the config plugin may have started services.
      Initializer::requestShutdown();
    }
    status = update(response[0]);

    /*
     * If the initial configuration includes a non-0 refresh, start an
     * additional service that sleeps and periodically regenerates the
     * configuration.
     */
    if (!started_thread_ && FLAGS_config_refresh >= 1) {
      Dispatcher::addService(std::make_shared<ConfigRefreshRunner>());
      started_thread_ = true;
    }
  }

  loaded_ = true;
  return status;
}

Status Config::load() {
  valid_ = false;
  auto config_plugin = RegistryFactory::get().getActive("config");
  if (!RegistryFactory::get().exists("config", config_plugin)) {
    LOG(WARNING) << "Missing config plugin: " << config_plugin;
    return Status(1, "Missing config plugin " + config_plugin);
  }

  return refresh();
}

void stripConfigComments(std::string& json) {
  std::string sink;

  boost::replace_all(json, "\\\n", "");
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

Status Config::updateSource(const std::string& source,
                            const std::string& json) {
  // Compute a 'synthesized' hash using the content before it is parsed.
  hashSource(source, json);

  {
    RecursiveLock lock(config_schedule_mutex_);
    // Remove all packs from this source.
    schedule_->removeAll(source);
    // Remove all files from this source.
    removeFiles(source);
  }

  // load the config (source.second) into a pt::ptree
  pt::ptree tree;
  try {
    auto clone = json;
    stripConfigComments(clone);
    std::stringstream json_stream;
    json_stream << clone;
    pt::read_json(json_stream, tree);
  } catch (const pt::json_parser::json_parser_error& e) {
    LOG(WARNING) << "Error parsing the config JSON: " << e.what();
    return Status(1, e.what());
  }

  // extract the "schedule" key and store it as the main pack
  auto& rf = RegistryFactory::get();
  if (tree.count("schedule") > 0 && !rf.external()) {
    auto& schedule = tree.get_child("schedule");
    pt::ptree main_pack;
    main_pack.add_child("queries", schedule);
    addPack("main", source, main_pack);
  }

  if (tree.count("scheduledQueries") > 0 && !rf.external()) {
    auto& scheduled_queries = tree.get_child("scheduledQueries");
    pt::ptree queries;
    for (const std::pair<std::string, pt::ptree>& query : scheduled_queries) {
      auto query_name = query.second.get<std::string>("name", "");
      if (query_name.empty()) {
        LOG(WARNING) << "Error getting name from legacy scheduled query";
        return Status(1, "Failed to get query name");
      }
      queries.add_child(query_name, query.second);
    }
    pt::ptree legacy_pack;
    legacy_pack.add_child("queries", queries);
    addPack("legacy_main", source, legacy_pack);
  }

  // extract the "packs" key into additional pack objects
  if (tree.count("packs") > 0 && !rf.external()) {
    auto& packs = tree.get_child("packs");
    for (const auto& pack : packs) {
      auto value = packs.get<std::string>(pack.first, "");
      if (value.empty()) {
        // The pack is a JSON object, treat the content as pack data.
        addPack(pack.first, source, pack.second);
      } else {
        genPack(pack.first, source, value);
      }
    }
  }

  applyParsers(source, tree, false);
  return Status(0, "OK");
}

Status Config::genPack(const std::string& name,
                       const std::string& source,
                       const std::string& target) {
  // If the pack value is a string (and not a JSON object) then it is a
  // resource to be handled by the config plugin.
  PluginResponse response;
  PluginRequest request = {
      {"action", "genPack"}, {"name", name}, {"value", target}};
  Registry::call("config", request, response);

  if (response.size() == 0 || response[0].count(name) == 0) {
    LOG(WARNING) << "Invalid plugin response";
    return Status(1, "Invalid plugin response");
  }

  try {
    auto clone = response[0][name];
    stripConfigComments(clone);
    pt::ptree pack_tree;
    std::stringstream pack_stream;
    pack_stream << clone;
    pt::read_json(pack_stream, pack_tree);
    addPack(name, source, pack_tree);
  } catch (const pt::json_parser::json_parser_error& /* e */) {
    LOG(WARNING) << "Error parsing the pack JSON: " << name;
    return Status(1, "Failed to parse pack");
  }
  return Status(0);
}

void Config::applyParsers(const std::string& source,
                          const pt::ptree& tree,
                          bool pack) {
  // Iterate each parser.
  RecursiveLock lock(config_schedule_mutex_);
  for (const auto& plugin : RegistryFactory::get().plugins("config_parser")) {
    std::shared_ptr<ConfigParserPlugin> parser = nullptr;
    try {
      parser = std::dynamic_pointer_cast<ConfigParserPlugin>(plugin.second);
    } catch (const std::bad_cast& /* e */) {
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
    parser->update(source, parser_config);
  }
}

Status Config::update(const std::map<std::string, std::string>& config) {
  // A config plugin may call update from an extension. This will update
  // the config instance within the extension process and the update must be
  // reflected in the core.
  if (RegistryFactory::get().external()) {
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

  if (loaded_) {
    // The config has since been loaded.
    // This update call is most likely a response to an async update request
    // from a config plugin. This request should request all plugins to update.
    for (const auto& registry : RegistryFactory::get().all()) {
      if (registry.first == "event_publisher" ||
          registry.first == "event_subscriber") {
        continue;
      }
      registry.second->configure();
    }

    // If events are enabled configure the subscribers before publishers.
    if (!FLAGS_disable_events) {
      RegistryFactory::get().registry("event_subscriber")->configure();
      RegistryFactory::get().registry("event_publisher")->configure();
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
    for (const auto& pack : schedule->packs_) {
      const auto& pack_queries = pack->getSchedule();
      if (pack_queries.count(query_name)) {
        return true;
      }
    }
    return false;
  };

  RecursiveLock lock(config_schedule_mutex_);
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
    } catch (const boost::bad_lexical_cast& /* e */) {
      // Erase the timestamp as is it potentially corrupt.
      VLOG(1) << "Potentially corrupted timestamp erased: " << saved_query;
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

void Config::reset() {
  schedule_ = std::make_shared<Schedule>();
  std::map<std::string, QueryPerformance>().swap(performance_);
  std::map<std::string, FileCategories>().swap(files_);
  std::map<std::string, std::string>().swap(hash_);
  valid_ = false;
  loaded_ = false;
  start_time_ = 0;

  // Also request each parse to reset state.
  for (const auto& plugin : RegistryFactory::get().plugins("config_parser")) {
    std::shared_ptr<ConfigParserPlugin> parser = nullptr;
    try {
      parser = std::dynamic_pointer_cast<ConfigParserPlugin>(plugin.second);
    } catch (const std::bad_cast& e) {
      VLOG(1) << "Error retrieving pointer: " << e.what();
      continue;
    }
    if (parser == nullptr || parser.get() == nullptr) {
      continue;
    }
    parser->reset();
  }
}

void ConfigParserPlugin::reset() {
  // Resets will clear all top-level keys from the parser's data store.
  for (auto& category : data_) {
    boost::property_tree::ptree().swap(category.second);
  }
}

void Config::recordQueryPerformance(const std::string& name,
                                    size_t delay,
                                    size_t size,
                                    const Row& r0,
                                    const Row& r1) {
  RecursiveLock lock(config_performance_mutex_);
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
    RecursiveLock lock(config_performance_mutex_);
    predicate(performance_.at(name));
  }
}

void Config::hashSource(const std::string& source, const std::string& content) {
  WriteLock wlock(config_hash_mutex_);
  hash_[source] = getBufferSHA1(content.c_str(), content.size());
}

Status Config::genHash(std::string& hash) {
  if (!valid_) {
    LOG(WARNING) << "Current config is not valid";
    return Status(1, "Invalid config");
  }

  WriteLock lock(config_hash_mutex_);
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
  hash = getBufferSHA1(buffer.data(), buffer.size());

  return Status(0, "OK");
}

const std::shared_ptr<ConfigParserPlugin> Config::getParser(
    const std::string& parser) {
  if (!RegistryFactory::get().exists("config_parser", parser, true)) {
    return nullptr;
  }

  auto plugin = RegistryFactory::get().plugin("config_parser", parser);
  // This is an error, need to check for existance (and not nullptr).
  return std::dynamic_pointer_cast<ConfigParserPlugin>(plugin);
}

void Config::files(
    std::function<void(const std::string& category,
                       const std::vector<std::string>& files)> predicate) {
  RecursiveLock lock(config_files_mutex_);
  for (const auto& it : files_) {
    for (const auto& category : it.second) {
      predicate(category.first, category.second);
    }
  }
}

Status ConfigPlugin::genPack(const std::string& name,
                             const std::string& value,
                             std::string& pack) {
  VLOG(1) << "Not implemented";
  return Status(1, "Not implemented");
}

Status ConfigPlugin::call(const PluginRequest& request,
                          PluginResponse& response) {
  if (request.count("action") == 0) {
    LOG(WARNING) << "Config plugins require an action in PluginRequest";
    return Status(1, "Config plugins missing action");
  }

  if (request.at("action") == "genConfig") {
    std::map<std::string, std::string> config;
    auto stat = genConfig(config);
    response.push_back(config);
    return stat;
  } else if (request.at("action") == "genPack") {
    if (request.count("name") == 0 || request.count("value") == 0) {
      LOG(WARNING) << "Missing request name or value";
      return Status(1, "Missing name/value");
    }
    std::string pack;
    auto stat = genPack(request.at("name"), request.at("value"), pack);
    response.push_back({{request.at("name"), pack}});
    return stat;
  } else if (request.at("action") == "update") {
    if (request.count("source") == 0 || request.count("data") == 0) {
      LOG(WARNING) << "Missing request source or data";
      return Status(1, "Missing source/data");
    }
    return Config::getInstance().update(
        {{request.at("source"), request.at("data")}});
  }
  LOG(ERROR) << "Config plugin action unknown: " << request.at("action");
  return Status(1, "Config plugin action unknown: " + request.at("action"));
}

Status ConfigParserPlugin::setUp() {
  for (const auto& key : keys()) {
    data_.put(key, "");
  }
  return Status(0, "OK");
}

void ConfigRefreshRunner::start() {
  while (!interrupted()) {
    // Cool off and time wait the configured period.
    // Apply this interruption initially as at t=0 the config was read.
    pauseMilli(FLAGS_config_refresh * 1000);
    // Since the pause occurs before the logic, we need to check for an
    // interruption request.
    if (interrupted()) {
      return;
    }

    VLOG(1) << "Refreshing configuration state";
    Config::getInstance().refresh();
  }
}
}
