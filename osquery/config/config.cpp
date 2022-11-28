/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <algorithm>
#include <chrono>
#include <functional>
#include <map>
#include <queue>
#include <string>
#include <vector>

#include <boost/algorithm/string/replace.hpp>
#include <boost/iterator/filter_iterator.hpp>

#include <osquery/config/config.h>
#include <osquery/config/packs.h>
#include <osquery/core/flagalias.h>
#include <osquery/core/flags.h>
#include <osquery/core/shutdown.h>
#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/database/database.h>
#include <osquery/dispatcher/dispatcher.h>
#include <osquery/events/eventfactory.h>
#include <osquery/events/events.h>
#include <osquery/hashing/hashing.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/trim.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/system/time.h>

namespace rj = rapidjson;

namespace osquery {
namespace {
/// Prefix to persist config data
const std::string kConfigPersistencePrefix{"config_persistence."};

/// Max depth that the JSON document representing the configuration can have
const int kMaxConfigDepth = 32;
/// Max size that the configuration, stripped from its comments, can have
const int kMaxConfigSize = 1024 * 1024;

using ConfigMap = std::map<std::string, std::string>;

std::atomic<bool> is_first_time_refresh(true);
}; // namespace

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

CLI_FLAG(bool,
         config_dump,
         false,
         "Dump the contents of the configuration, then exit");

CLI_FLAG(uint64,
         config_refresh,
         0,
         "Optional interval in seconds to re-read configuration");
FLAG_ALIAS(google::uint64, config_tls_refresh, config_refresh);

/// How long to wait when config update fails
CLI_FLAG(uint64,
         config_accelerated_refresh,
         300,
         "Interval to wait if reading a configuration fails");

CLI_FLAG(bool,
         config_enable_backup,
         false,
         "Backup config and use it when refresh fails");

FLAG_ALIAS(google::uint64,
           config_tls_accelerated_refresh,
           config_accelerated_refresh);

DECLARE_string(config_plugin);
DECLARE_string(pack_delimiter);

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
Mutex config_refresh_mutex_;
Mutex config_backup_mutex_;

/// Several config methods require enumeration via predicate lambdas.
RecursiveMutex config_schedule_mutex_;
RecursiveMutex config_files_mutex_;
RecursiveMutex config_performance_mutex_;

using PackRef = std::unique_ptr<Pack>;

/**
 * The schedule is an iterable collection of Packs. When you iterate through
 * a schedule, you only get the packs that should be running on the host that
 * you're currently operating on.
 */
class Schedule : private boost::noncopyable {
 public:
  /// Under the hood, the schedule is just a list of the Pack objects
  using container = std::vector<PackRef>;

  /**
   * @brief Create a schedule maintained by the configuration.
   *
   * This will check for previously executing queries. If any query was
   * executing it is considered in a 'dirty' state and should generate logs.
   * The schedule may also choose to denylist this query.
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
    bool operator()(const PackRef& pack) const;
  };

  /// Add a pack to the schedule
  void add(PackRef pack);

  /// Remove a pack, by name.
  void remove(const std::string& pack);

  /// Remove a pack by name and source.
  void remove(const std::string& pack, const std::string& source);

  /// Remove all packs by source.
  void removeAll(const std::string& source);

  /// Boost gives us a nice template for maintaining the state of the iterator
  using iterator = boost::filter_iterator<Step, container::iterator>;

  iterator begin();

  iterator end();

  PackRef& last();

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
   * @brief List of denylisted queries.
   *
   * A list of queries that are denylisted from executing due to prior
   * failures. If a query caused a worker to fail it will be recorded during
   * the next execution and saved to the denylist.
   */
  std::map<std::string, uint64_t> denylist_;

 private:
  friend class Config;
};

bool Schedule::Step::operator()(const PackRef& pack) const {
  return pack->shouldPackExecute();
}

void Schedule::add(PackRef pack) {
  remove(pack->getName(), pack->getSource());
  packs_.push_back(std::move(pack));
}

void Schedule::remove(const std::string& pack) {
  remove(pack, "");
}

void Schedule::remove(const std::string& pack, const std::string& source) {
  auto new_end = std::remove_if(
      packs_.begin(), packs_.end(), [pack, source](const PackRef& p) {
        if (p->getName() == pack &&
            (p->getSource() == source || source == "")) {
          Config::get().removeFiles(source + FLAGS_pack_delimiter +
                                    p->getName());
          return true;
        }
        return false;
      });
  packs_.erase(new_end, packs_.end());
}

void Schedule::removeAll(const std::string& source) {
  auto new_end =
      std::remove_if(packs_.begin(), packs_.end(), [source](const PackRef& p) {
        if (p->getSource() == source) {
          Config::get().removeFiles(source + FLAGS_pack_delimiter +
                                    p->getName());
          return true;
        }
        return false;
      });
  packs_.erase(new_end, packs_.end());
}

Schedule::iterator Schedule::begin() {
  return Schedule::iterator(packs_.begin(), packs_.end());
}

Schedule::iterator Schedule::end() {
  return Schedule::iterator(packs_.end(), packs_.end());
}

PackRef& Schedule::last() {
  return packs_.back();
}

/**
 * @brief A thread that periodically reloads configuration state.
 *
 * This refresh runner thread can refresh any configuration plugin.
 * It may accelerate the time between checks if the configuration fails to load.
 * For configurations pulled from the network this assures that configuration
 * is fresh when re-attaching.
 */
class ConfigRefreshRunner : public InternalRunnable {
 public:
  ConfigRefreshRunner() : InternalRunnable("ConfigRefreshRunner") {}

  /// A simple wait/interruptible lock.
  void start() override;

 private:
  /// The current refresh rate in seconds.
  std::atomic<uint64_t> refresh_sec_{0};

 private:
  friend class Config;
};

void restoreScheduleDenylist(std::map<std::string, uint64_t>& denylist) {
  std::string content;
  getDatabaseValue(kPersistentSettings, kFailedQueries, content);
  auto denylist_pairs = osquery::split(content, ":");
  if (denylist_pairs.size() == 0 || denylist_pairs.size() % 2 != 0) {
    // Nothing in the denylist, or malformed data.
    return;
  }

  uint64_t current_time = getUnixTime();
  for (size_t i = 0; i < denylist_pairs.size() / 2; i++) {
    // Fill in a mapping of query name to time the denylist expires.
    auto expire = tryTo<long long>(denylist_pairs[(i * 2) + 1], 10).takeOr(0ll);
    if (expire > 0 && current_time < (uint64_t)expire) {
      denylist[denylist_pairs[(i * 2)]] = (uint64_t)expire;
    }
  }
}

void saveScheduleDenylist(const std::map<std::string, uint64_t>& denylist) {
  std::string content;
  for (const auto& query : denylist) {
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
  // Parse the schedule's query denylist from backing storage.
  restoreScheduleDenylist(denylist_);

  // Check if any queries were executing when the tool last stopped.
  getDatabaseValue(kPersistentSettings, kExecutingQuery, failed_query_);
  if (!failed_query_.empty()) {
    LOG(WARNING) << "Scheduled query may have failed: " << failed_query_;
    setDatabaseValue(kPersistentSettings, kExecutingQuery, "");
    // Add this query name to the denylist and save the denylist.
    denylist_[failed_query_] = getUnixTime() + 86400;
    saveScheduleDenylist(denylist_);
  }
}

Config::Config()
    : schedule_(std::make_unique<Schedule>()),
      valid_(false),
      refresh_runner_(std::make_shared<ConfigRefreshRunner>()) {}

Config& Config::get() {
  static Config instance;
  return instance;
}

void Config::addPack(const std::string& name,
                     const std::string& source,
                     const rj::Value& obj) {
  assert(obj.IsObject());

  auto addSinglePack = ([this, &source](const std::string pack_name,
                                        const rj::Value& pack_obj) {
    RecursiveLock wlock(config_schedule_mutex_);
    try {
      schedule_->add(std::make_unique<Pack>(pack_name, source, pack_obj));
#ifndef OSQUERY_IS_FUZZING
      bool should_pack_execute = schedule_->last()->shouldPackExecute();
#else
      bool should_pack_execute = true;
#endif
      if (should_pack_execute) {
        applyParsers(source + FLAGS_pack_delimiter + pack_name, pack_obj, true);
      }
    } catch (const std::exception& e) {
      LOG(WARNING) << "Error adding pack: " << pack_name << ": " << e.what();
    }
  });

  if (name == "*") {
    // This is a multi-pack, expect the config plugin to have generated a
    // "name": {pack-content} response similar to embedded pack content
    // within the configuration.
    for (const auto& pack : obj.GetObject()) {
      if (!pack.value.IsObject()) {
        LOG(WARNING) << "Error parsing pack: " << pack.name.GetString()
                     << ": the value should be an object";
        continue;
      }
      addSinglePack(pack.name.GetString(), pack.value);
    }
  } else {
    addSinglePack(name, obj);
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

/**
 * @brief Return true if the failed query is no longer denylisted.
 *
 * There are two scenarios where a denylisted query becomes 'undenylisted'.
 * The first is simple, the amount of time it was denylisted for has expired.
 * The second is more complex, the query failed but the schedule has requested
 * that the query should not be denylisted.
 *
 * @param blt The time the query was originally denylisted.
 * @param query The scheduled query and its options.
 */
static inline bool denylistExpired(uint64_t blt, const ScheduledQuery& query) {
  if (getUnixTime() > blt) {
    return true;
  }

  if (!enforceEventsDenylist(query.query)) {
    // This is an events-based query and denylisting is not being enforced for
    // these types of queries.
    return true;
  }

  auto blo = query.options.find("denylist");
  if (blo != query.options.end() && blo->second == false) {
    // The schedule requested that we do not denylist this query.
    return true;
  }
  return false;
}

void Config::scheduledQueries(
    std::function<void(std::string name, const ScheduledQuery& query)>
        predicate,
    bool denylisted) const {
  RecursiveLock lock(config_schedule_mutex_);
  for (PackRef& pack : *schedule_) {
    for (auto& it : pack->getSchedule()) {
      std::string name = it.first;
      // The query name may be synthetic.
      if (pack->getName() != "main") {
        name = "pack" + FLAGS_pack_delimiter + pack->getName() +
               FLAGS_pack_delimiter + it.first;
      }

      // They query may have failed and been added to the schedule's denylist.
      auto denylisted_query = schedule_->denylist_.find(name);
      if (denylisted_query != schedule_->denylist_.end()) {
        if (denylistExpired(denylisted_query->second, it.second)) {
          // The denylisted query passed the expiration time (remove).
          schedule_->denylist_.erase(denylisted_query);
          saveScheduleDenylist(schedule_->denylist_);
          it.second.denylisted = false;
        } else {
          // The query is still denylisted.
          it.second.denylisted = true;
          if (!denylisted) {
            // The caller does not want denylisted queries.
            continue;
          }
        }
      }

      // Call the predicate.
      predicate(std::move(name), it.second);

      if (shutdownRequested()) {
        break;
      }
    }
  }
}

void Config::packs(std::function<void(const Pack& pack)> predicate) const {
  RecursiveLock lock(config_schedule_mutex_);
  for (PackRef& pack : schedule_->packs_) {
    predicate(std::cref(*pack.get()));
  }
}

Status Config::refresh() {
  PluginResponse response;
  auto status = Registry::call("config", {{"action", "genConfig"}}, response);

  WriteLock lock(config_refresh_mutex_);
  if (!status.ok()) {
    if (FLAGS_config_refresh > 0 && getRefresh() == FLAGS_config_refresh) {
      VLOG(1) << "Using accelerated configuration delay";
      setRefresh(FLAGS_config_accelerated_refresh);
    }

    loaded_ = true;
    if (FLAGS_config_enable_backup && is_first_time_refresh.exchange(false)) {
      LOG(INFO) << "Backing up configuration";
      const auto result = restoreConfigBackup();
      if (!result) {
        return Status::failure(result.getError().getMessage());
      } else {
        update(*result);
      }
    }
    return status;
  } else if (getRefresh() != FLAGS_config_refresh) {
    VLOG(1) << "Normal configuration delay restored";
    setRefresh(FLAGS_config_refresh);
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
      VLOG(1) << "Requesting shutdown after dumping config";
      // Don't force because the config plugin may have started services.
      requestShutdown();
      return Status::success();
    }
    status = update(response[0]);
  }

  is_first_time_refresh = false;
  loaded_ = true;
  return status;
}

void Config::setRefresh(uint64_t refresh_sec) {
  refresh_runner_->refresh_sec_ = refresh_sec;
}

uint64_t Config::getRefresh() const {
  return refresh_runner_->refresh_sec_;
}

Status Config::load() {
  valid_ = false;
  auto config_plugin = RegistryFactory::get().getActive("config");
  if (!RegistryFactory::get().exists("config", config_plugin)) {
    return Status(1, "Missing config plugin " + config_plugin);
  }

  // Set the initial and optional refresh value.
  setRefresh(FLAGS_config_refresh);

  /*
   * If the initial configuration includes a non-0 refresh, start an
   * additional service that sleeps and periodically regenerates the
   * configuration.
   */
  if (!FLAGS_config_check && !started_thread_ && getRefresh() > 0) {
    Dispatcher::addService(refresh_runner_);
    started_thread_ = true;
  }

  return refresh();
}

void stripConfigComments(std::string& json) {
  std::string sink;

  boost::replace_all(json, "\\\n", "");
  for (auto& line : osquery::vsplit(json, '\n')) {
    auto trimmed_line = osquery::trim(line);
    if (trimmed_line.size() > 0 && trimmed_line[0] == '#') {
      continue;
    }
    if (trimmed_line.size() > 1 && trimmed_line[0] == '/' &&
        trimmed_line[1] == '/') {
      continue;
    }
    sink += trimmed_line;
    sink += '\n';
  }
  json = sink;
}

Expected<ConfigMap, Config::RestoreConfigError> Config::restoreConfigBackup() {
  LOG(INFO) << "Restoring backed up config from the database";
  std::vector<std::string> keys;
  ConfigMap config;

  WriteLock lock(config_backup_mutex_);
  scanDatabaseKeys(kPersistentSettings, keys, kConfigPersistencePrefix);

  for (const auto& key : keys) {
    std::string value;
    Status status = getDatabaseValue(kPersistentSettings, key, value);
    if (!status.ok()) {
      LOG(ERROR)
          << "restoreConfigBackup database failed to retrieve config for key "
          << key;
      return createError(Config::RestoreConfigError::DatabaseError)
             << "Could not retrieve value for the key: " << key;
    }
    config[key.substr(kConfigPersistencePrefix.length())] = std::move(value);
  }

  return config;
}

void Config::backupConfig(const ConfigMap& config) {
  LOG(INFO) << "BackupConfig started";
  std::vector<std::string> keys;

  WriteLock lock(config_backup_mutex_);
  scanDatabaseKeys(kPersistentSettings, keys, kConfigPersistencePrefix);
  for (const auto& key : keys) {
    if (config.find(key.substr(kConfigPersistencePrefix.length())) ==
        config.end()) {
      deleteDatabaseValue(kPersistentSettings, key);
    }
  }

  for (const auto& source : config) {
    setDatabaseValue(kPersistentSettings,
                     kConfigPersistencePrefix + source.first,
                     source.second);
  }
}

Status Config::validateConfig(const JSON& document) {
  const auto& rapidjson_doc = document.doc();
  if (!rapidjson_doc.IsObject()) {
    return Status::failure(
        "The root of the config JSON document has to be an Object");
  }

  const rapidjson::Value& root_node = rapidjson_doc;
  std::queue<std::reference_wrapper<const rapidjson::Value>> nodes;
  nodes.push(root_node);

  std::size_t node_count = nodes.size();
  int depth = 0;

  while (node_count > 0 && depth < kMaxConfigDepth) {
    while (node_count > 0) {
      const auto& node = nodes.front().get();
      nodes.pop();

      if (node.IsObject()) {
        for (rapidjson::Value::ConstMemberIterator itr = node.MemberBegin();
             itr != node.MemberEnd();
             ++itr) {
          nodes.push(itr->value);
        }
      } else if (node.IsArray()) {
        for (size_t i = 0; i < node.Size(); ++i) {
          nodes.push(node[i]);
        }
      }

      --node_count;
    }

    ++depth;
    node_count = nodes.size();
  }

  if (depth == kMaxConfigDepth && node_count != 0) {
    return Status::failure(
        "Configuration has too many "
        "nesting levels!");
  }

  return Status::success();
}

Status Config::updateSource(const std::string& source,
                            const std::string& json) {
  // Compute a 'synthesized' hash using the content before it is parsed.
  if (!hashSource(source, json)) {
    // This source did not change, the returned status allows the caller to
    // choose to reconfigure if any sources had changed.
    return Status(2);
  }

  {
    RecursiveLock lock(config_schedule_mutex_);
    // Remove all packs from this source.
    schedule_->removeAll(source);
    // Remove all files from this source.
    removeFiles(source);
  }

  // load the config (source.second) into a JSON object.
  auto doc = JSON::newObject();
  auto clone = json;
  stripConfigComments(clone);

  // Since we use iterative parsing, we limit the size of the JSON
  // string to a sane value to avoid memory exhaustion.
  if (clone.size() > kMaxConfigSize) {
    return Status::failure(
        "Error parsing the config JSON: the config size exceeds the limit "
        "of " +
        std::to_string(kMaxConfigSize) + " bytes");
  }

  if (!doc.fromString(clone, JSON::ParseMode::Iterative) ||
      !doc.doc().IsObject()) {
    return Status::failure("Error parsing the config JSON");
  }

  auto status = validateConfig(doc);
  if (!status.ok()) {
    return Status::failure("Error validating the config JSON: " +
                           status.getMessage());
  }

  // extract the "schedule" key and store it as the main pack
  auto& rf = RegistryFactory::get();
  if (doc.doc().HasMember("schedule") && !rf.external()) {
    auto& schedule = doc.doc()["schedule"];
    if (schedule.IsObject()) {
      auto main_doc = JSON::newObject();
      auto queries_obj = main_doc.getObject();
      main_doc.copyFrom(schedule, queries_obj);
      main_doc.add("queries", queries_obj);
      addPack("main", source, main_doc.doc());
    }
  }

  // extract the "packs" key into additional pack objects
  if (doc.doc().HasMember("packs") && !rf.external()) {
    auto& packs = doc.doc()["packs"];
    if (packs.IsObject()) {
      for (const auto& pack : packs.GetObject()) {
        std::string pack_name = pack.name.GetString();
        if (pack.value.IsObject()) {
          // The pack is a JSON object, treat the content as pack data.
          addPack(pack_name, source, pack.value);
        } else if (pack.value.IsString()) {
          genPack(pack_name, source, pack.value.GetString());
        }
      }
    }
  }

  applyParsers(source, doc.doc(), false);
  return Status::success();
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
    return Status(1, "Invalid plugin response");
  }

  auto clone = response[0][name];
  if (clone.empty()) {
    LOG(WARNING) << "Error reading the query pack named: " << name;
    return Status::success();
  }

  stripConfigComments(clone);
  auto doc = JSON::newObject();
  if (!doc.fromString(clone) || !doc.doc().IsObject()) {
    LOG(WARNING) << "Error parsing the \"" << name << "\" pack JSON";
  } else {
    addPack(name, source, doc.doc());
  }

  return Status::success();
}

void Config::applyParsers(const std::string& source,
                          const rj::Value& obj,
                          bool pack) {
  assert(obj.IsObject());

  auto applyParser = [=](const std::shared_ptr<ConfigParserPlugin>& parser,
                         const std::string& source,
                         const rj::Value& obj) {
    // For each key requested by the parser, add a property tree reference.
    std::map<std::string, JSON> parser_config;
    for (const auto& key : parser->keys()) {
      if (obj.HasMember(key) && !obj[key].IsNull()) {
        if (!obj[key].IsArray() && !obj[key].IsObject()) {
          LOG(WARNING) << "Error config " << key
                       << " should be an array or object";
          continue;
        }

        auto doc = JSON::newFromValue(obj[key]);
        parser_config.emplace(key, std::move(doc));
      }
    }
    // The config parser plugin will receive a copy of each property tree for
    // each top-level-config key. The parser may choose to update the config's
    // internal state
    parser->update(source, parser_config);
  };

  auto getParser = [=](const PluginRef& plugin, const std::string& name) {
    std::shared_ptr<ConfigParserPlugin> parser = nullptr;
    try {
      parser = std::dynamic_pointer_cast<ConfigParserPlugin>(plugin);
    } catch (const std::bad_cast& /* e */) {
      LOG(ERROR) << "Error casting config parser plugin: " << name;
    }
    return parser;
  };

  RecursiveLock lock(config_schedule_mutex_);
  auto plugins = RegistryFactory::get().plugins("config_parser");

  // Always apply the options parser first, others may depend on flags/options.
  auto options_plugin = plugins.find("options");
  if (options_plugin != plugins.end()) {
    auto parser = getParser(options_plugin->second, options_plugin->first);
    if (parser != nullptr && parser.get() != nullptr) {
      applyParser(parser, source, obj);
    }
  }

  // Iterate each parser.
  for (const auto& plugin : plugins) {
    if (plugin.first == "options") {
      continue;
    }
    auto parser = getParser(plugin.second, plugin.first);
    if (parser != nullptr && parser.get() != nullptr) {
      applyParser(parser, source, obj);
    }
  }
}

Status Config::update(const ConfigMap& config) {
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
      auto status = Registry::call("config", "update", request);
      if (!status.ok()) {
        // If something goes wrong, do not go with update further
        return status;
      }
    }
  }

  // Iterate though each source and overwrite config data.
  // This will add/overwrite pack data, append to the schedule, change watched
  // files, set options, etc.
  // Before this occurs, take an opportunity to purge stale state.
  purge();

  bool needs_reconfigure = false;
  for (const auto& source : config) {
    auto status = updateSource(source.first, source.second);
    if (status.getCode() == 2) {
      // The source content did not change.
      continue;
    }

    if (!status.ok()) {
      LOG(ERROR) << "updateSource failed to parse config, of source: "
                 << source.first << " and content: " << source.second;
      return status;
    }
    // If a source was updated and the content has changed, then the registry
    // should be reconfigured. File watches may have changed, etc.
    needs_reconfigure = true;
  }

  if (loaded_ && needs_reconfigure) {
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

    EventFactory::configUpdate();
  }

  // This cannot be under the previous if block because on extensions loaded_
  // allways false.
  if (needs_reconfigure) {
    std::string loggers = RegistryFactory::get().getActive("logger");
    for (const auto& logger : osquery::split(loggers, ",")) {
      LOG(INFO) << "Calling configure for logger " << logger;
      PluginRef plugin = Registry::get().plugin("logger", logger);

      if (plugin) {
        plugin->configure();
      }
    }
  }

  if (FLAGS_config_enable_backup) {
    backupConfig(config);
  }

  return Status::success();
}

void Config::purge() {
  // The first use of purge is removing expired query results.
  std::vector<std::string> saved_queries;
  scanDatabaseKeys(kQueries, saved_queries);

  auto queryExists = [schedule = static_cast<const Schedule*>(schedule_.get())](
                         const std::string& query_name) {
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
    uint64_t last_executed = 0;
    try {
      last_executed = boost::lexical_cast<uint64_t>(content);
    } catch (const boost::bad_lexical_cast& /* e */) {
      // Erase the timestamp as is it potentially corrupt.
      deleteDatabaseValue(kPersistentSettings, "timestamp." + saved_query);
      continue;
    }

    if (last_executed < getUnixTime() - 592200) {
      // Query has not run in the last week, expire results and interval.
      deleteDatabaseValue(kQueries, saved_query);
      deleteDatabaseValue(kQueries, saved_query + "epoch");
      deleteDatabaseValue(kPersistentSettings, "interval." + saved_query);
      deleteDatabaseValue(kPersistentSettings, "timestamp." + saved_query);
      VLOG(1) << "Expiring results for scheduled query: " << saved_query;
    }
  }
}

void Config::reset() {
  setStartTime(getUnixTime());

  schedule_ = std::make_unique<Schedule>();
  std::map<std::string, QueryPerformance>().swap(performance_);
  std::map<std::string, FileCategories>().swap(files_);
  std::map<std::string, std::string>().swap(hash_);
  valid_ = false;
  loaded_ = false;
  is_first_time_refresh = true;

  refresh_runner_ = std::make_shared<ConfigRefreshRunner>();
  started_thread_ = false;

  // Also request each parse to reset state.
  for (const auto& plugin : RegistryFactory::get().plugins("config_parser")) {
    std::shared_ptr<ConfigParserPlugin> parser = nullptr;
    try {
      parser = std::dynamic_pointer_cast<ConfigParserPlugin>(plugin.second);
    } catch (const std::bad_cast& /* e */) {
      continue;
    }
    if (parser == nullptr || parser.get() == nullptr) {
      continue;
    }
    parser->reset();
    parser->setUp();
  }
}

void ConfigParserPlugin::reset() {
  // Resets will clear all top-level keys from the parser's data store.
  auto doc = JSON::newObject();

  for (auto& category : data_.doc().GetObject()) {
    auto obj = doc.getObject();
    doc.add(category.name.GetString(), obj, doc.doc());
  }

  data_ = std::move(doc);
}

void Config::recordQueryPerformance(const std::string& name,
                                    uint64_t delay_ms,
                                    uint64_t size,
                                    const Row& r0,
                                    const Row& r1) {
  RecursiveLock lock(config_performance_mutex_);
  if (performance_.count(name) == 0) {
    performance_[name] = QueryPerformance();
  }

  // Grab access to the non-const schedule item.
  auto& query = performance_.at(name);
  if (!r1.at("user_time").empty() && !r0.at("user_time").empty()) {
    auto ut1 = tryTo<long long>(r1.at("user_time"));
    auto ut0 = tryTo<long long>(r0.at("user_time"));
    auto diff = (ut1 && ut0) ? ut1.take() - ut0.take() : 0;
    if (diff > 0) {
      query.user_time += diff;
      query.last_user_time = diff;
    }
  }

  if (!r1.at("system_time").empty() && !r0.at("system_time").empty()) {
    auto st1 = tryTo<long long>(r1.at("system_time"));
    auto st0 = tryTo<long long>(r0.at("system_time"));
    auto diff = (st1 && st0) ? st1.take() - st0.take() : 0;
    if (diff > 0) {
      query.system_time += diff;
      query.last_system_time = diff;
    }
  }

  if (!r1.at("resident_size").empty() && !r0.at("resident_size").empty()) {
    auto rs1 = tryTo<long long>(r1.at("resident_size"));
    auto rs0 = tryTo<long long>(r0.at("resident_size"));
    auto diff = (rs1 && rs0) ? rs1.take() - rs0.take() : 0;
    if (diff > 0) {
      // Memory is stored as an average of RSS changes between query executions.
      query.average_memory = (query.average_memory * query.executions) + diff;
      query.average_memory = (query.average_memory / (query.executions + 1));
      query.last_memory = diff;
    }
  }

  query.last_wall_time_ms = delay_ms;
  query.wall_time_ms += delay_ms;
  query.wall_time += (delay_ms / 1000);
  query.output_size += size;
  query.executions += 1;
  query.last_executed = getUnixTime();

  /* Clear the executing query only if a resource limit has not been hit.
     This is used by the next worker execution to denylist a query
     that triggered a watchdog resource limit. */
  if (!Initializer::isResourceLimitHit()) {
    setDatabaseValue(kPersistentSettings, kExecutingQuery, "");
  }
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
    std::function<void(const QueryPerformance& query)> predicate) const {
  if (performance_.count(name) > 0) {
    RecursiveLock lock(config_performance_mutex_);
    predicate(performance_.at(name));
  }
}

bool Config::hashSource(const std::string& source, const std::string& content) {
  Hash hash(HASH_TYPE_SHA1);
  hash.update(content.c_str(), content.size());
  auto new_hash = hash.digest();

  WriteLock wlock(config_hash_mutex_);
  if (hash_[source] == new_hash) {
    return false;
  }
  hash_[source] = new_hash;
  return true;
}

Status Config::genHash(std::string& hash) const {
  WriteLock lock(config_hash_mutex_);
  if (!valid_) {
    return Status(1, "Current config is not valid");
  }

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

  Hash new_hash(HASH_TYPE_SHA1);
  new_hash.update(buffer.data(), buffer.size());
  hash = new_hash.digest();

  return Status::success();
}

std::string Config::getHash(const std::string& source) const {
  WriteLock lock(config_hash_mutex_);
  if (!hash_.count(source)) {
    return std::string();
  }
  return hash_.at(source);
}

const std::shared_ptr<ConfigParserPlugin> Config::getParser(
    const std::string& parser) {
  if (!RegistryFactory::get().exists("config_parser", parser, true)) {
    return nullptr;
  }

  auto plugin = RegistryFactory::get().plugin("config_parser", parser);
  // This is an error, need to check for existence (and not nullptr).
  return std::dynamic_pointer_cast<ConfigParserPlugin>(plugin);
}

void Config::files(std::function<void(const std::string& category,
                                      const std::vector<std::string>& files)>
                       predicate) const {
  RecursiveLock lock(config_files_mutex_);
  for (const auto& it : files_) {
    for (const auto& category : it.second) {
      predicate(category.first, category.second);
    }
  }
}

Config::~Config() = default;

Status ConfigPlugin::genPack(const std::string& name,
                             const std::string& value,
                             std::string& pack) {
  return Status(1, "Not implemented");
}

Status ConfigPlugin::call(const PluginRequest& request,
                          PluginResponse& response) {
  auto action = request.find("action");
  if (action == request.end()) {
    return Status::failure("Config plugins require an action");
  }

  if (action->second == "genConfig") {
    ConfigMap config;
    auto stat = genConfig(config);
    response.push_back(config);
    return stat;
  } else if (action->second == "genPack") {
    auto name = request.find("name");
    auto value = request.find("value");
    if (name == request.end() || value == request.end()) {
      return Status(1, "Missing name or value");
    }

    std::string pack;
    auto stat = genPack(name->second, value->second, pack);
    response.push_back({{name->second, pack}});
    return stat;
  } else if (action->second == "update") {
    auto source = request.find("source");
    auto data = request.find("data");
    if (source == request.end() || data == request.end()) {
      return Status(1, "Missing source or data");
    }

    return Config::get().update({{source->second, data->second}});
  } else if (action->second == "option") {
    auto name = request.find("name");
    if (name == request.end()) {
      return Status(1, "Missing option name");
    }

    response.push_back(
        {{"name", name->second}, {"value", Flag::getValue(name->second)}});
    return Status::success();
  }
  return Status(1, "Config plugin action unknown: " + action->second);
}

Status ConfigParserPlugin::setUp() {
  for (const auto& key : keys()) {
    auto obj = data_.getObject();
    data_.add(key, obj);
  }
  return Status::success();
}

void ConfigRefreshRunner::start() {
  while (!interrupted()) {
    // Cool off and time wait the configured period.
    // Apply this interruption initially as at t=0 the config was read.
    pause(std::chrono::seconds(refresh_sec_));
    // Since the pause occurs before the logic, we need to check for an
    // interruption request.
    if (interrupted()) {
      return;
    }

    VLOG(1) << "Refreshing configuration state";
    Config::get().refresh();
  }
}
} // namespace osquery
