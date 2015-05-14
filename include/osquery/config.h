/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <map>
#include <memory>
#include <vector>

#include <boost/noncopyable.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/thread/shared_mutex.hpp>

#include <osquery/database/results.h>
#include <osquery/flags.h>
#include <osquery/registry.h>
#include <osquery/status.h>

namespace pt = boost::property_tree;

namespace osquery {

/// The builder or invoker may change the default config plugin.
DECLARE_string(config_plugin);

/**
 * @brief A native representation of osquery configuration data.
 *
 * When you use osquery::Config::getInstance(), you are getting a singleton
 * handle to interact with the data stored in an instance of this struct.
 */
struct ConfigData {
  /// A vector of all of the queries that are scheduled to execute.
  std::map<std::string, ScheduledQuery> schedule;
  std::map<std::string, std::string> options;
  std::map<std::string, std::vector<std::string> > files;
  /// All data catches optional/plugin-parsed configuration keys.
  pt::ptree all_data;
};

class ConfigParserPlugin;
typedef std::shared_ptr<ConfigParserPlugin> ConfigPluginRef;

/**
 * @brief A singleton that exposes accessors to osquery's configuration data.
 *
 * osquery has two types on configurations. Things that don't change during
 * the execution of the process should be configured as command-line
 * arguments. Things that can change during the lifetime of program execution
 * should be defined using the osquery::config::Config class and the pluggable
 * plugin interface that is included with it.
 */
class Config : private boost::noncopyable {
 public:
  /**
   * @brief The primary way to access the Config singleton.
   *
   * osquery::config::Config::getInstance() provides access to the Config
   * singleton
   *
   * @code{.cpp}
   *   auto config = osquery::config::Config::getInstance();
   * @endcode
   *
   * @return a singleton instance of Config.
   */
  static Config& getInstance() {
    static Config cfg;
    return cfg;
  }

  /**
   * @brief Call the genConfig method of the config retriever plugin.
   *
   * This may perform a resource load such as TCP request or filesystem read.
   */
  static Status load();

  /**
   * @brief Update the internal config data.
   *
   * @param config A map of domain or namespace to config data.
   * @return If the config changes were applied.
   */
  static Status update(const std::map<std::string, std::string>& config);

  /**
   * @brief Calculate the has of the osquery config
   *
   * @return The MD5 of the osquery config
   */
  static Status getMD5(std::string& hashString);

  /**
   * @brief Adds a new query to the schedule queries
   *
   */
  static void addScheduledQuery(const std::string name, const std::string query, const int interval);

  /**
   * @brief Check to ensure that the config is accessible and properly
   * formatted
   *
   * @return an instance of osquery::Status, indicating the success or failure
   * of the operation.
   */
  static Status checkConfig();

 private:
  /**
   * @brief Default constructor.
   *
   * Since instances of Config should only be created via getInstance(),
   * Config's constructor is private
   */
  Config() : force_merge_success_(false) {}
  ~Config(){}
  Config(Config const&);
  void operator=(Config const&);

  /**
   * @brief Uses the specified config retriever to populate a string with the
   * config JSON.
   *
   * Internally, genConfig checks to see if there was a config retriever
   * specified on the command-line. If there was, it checks to see if that
   * config retriever actually exists. If it does, it gets used to generate
   * configuration data. If it does not, an error is logged.
   *
   * @return status indicating the success or failure of the operation.
   */
  static Status genConfig();

  /// Merge a retrieved config source JSON into a working ConfigData.
  static Status mergeConfig(const std::string& source, ConfigData& conf);

 public:
  /**
   * @brief Record performance (monitoring) information about a scheduled query.
   *
   * The daemon and query scheduler will optionally record process metadata
   * before and after executing each query. This can be compared and reported
   * on an interval or within the osquery_schedule table.
   *
   * The config consumes and calculates the optional performance differentials.
   * It would also be possible to store this in the RocksDB backing store or
   * report directly to a LoggerPlugin sink. The Config is the most appropriate
   * as the metrics are transient to the process running the schedule and apply
   * to the updates/changes reflected in the schedule, from the config.
   *
   * @param name The unique name of the scheduled item
   * @param delay Number of seconds (wall time) taken by the query
   * @param size Number of characters generated by query
   * @param t0 the process row before the query
   * @param t1 the process row after the query
   */
  static void recordQueryPerformance(const std::string& name,
                                     size_t delay,
                                     size_t size,
                                     const Row& t0,
                                     const Row& t1);

 private:
  /// The raw osquery config data in a native format
  ConfigData data_;

  /// The raw JSON source map from the config plugin.
  std::map<std::string, std::string> raw_;

  /// The reader/writer config data mutex.
  boost::shared_mutex mutex_;

  /// Enforce merge success.
  bool force_merge_success_;

 private:
  static const pt::ptree& getParsedData(const std::string& parser);
  static const ConfigPluginRef getParser(const std::string& parser);

  /// A default, empty property tree used when a missing parser is requested.
  pt::ptree empty_data_;

 private:
  /// Config accessors, `ConfigDataInstance`, are the forced use of the config
  /// data. This forces the caller to use a shared read lock.
  friend class ConfigDataInstance;

 private:
  FRIEND_TEST(ConfigTests, test_locking);
};

/**
 * @brief All accesses to the Config's data must request a ConfigDataInstance.
 *
 * This class will request a read-only lock of the config's changeable internal
 * data structures such as query schedule, options, monitored files, etc.
 *
 * Since a variable config plugin may implement `update` calls, internal uses
 * of config data needs simple read and write locking.
 */
class ConfigDataInstance {
 public:
  ConfigDataInstance() : lock_(Config::getInstance().mutex_) {}
  ~ConfigDataInstance() { lock_.unlock(); }

  /// Helper accessor for Config::data_.schedule.
  const std::map<std::string, ScheduledQuery> schedule() const {
    return Config::getInstance().data_.schedule;
  }

  /// Helper accessor for Config::data_.options.
  const std::map<std::string, std::string>& options() const {
    return Config::getInstance().data_.options;
  }

  /// Helper accessor for Config::data_.files.
  const std::map<std::string, std::vector<std::string> >& files() const {
    return Config::getInstance().data_.files;
  }

  const pt::ptree& getParsedData(const std::string& parser) const {
    return Config::getParsedData(parser);
  }

  const ConfigPluginRef getParser(const std::string& parser) const {
    return Config::getParser(parser);
  }

  /// Helper accessor for Config::data_.all_data.
  const pt::ptree& data() const { return Config::getInstance().data_.all_data; }

 private:
  /// A read lock on the reader/writer config data accessor/update mutex.
  boost::shared_lock<boost::shared_mutex> lock_;
};

/**
 * @brief Superclass for the pluggable config component.
 *
 * In order to make the distribution of configurations to hosts running
 * osquery, we take advantage of a plugin interface which allows you to
 * integrate osquery with your internal configuration distribution mechanisms.
 * You may use ZooKeeper, files on disk, a custom solution, etc. In order to
 * use your specific configuration distribution system, one simply needs to
 * create a custom subclass of ConfigPlugin. That subclass should implement
 * the ConfigPlugin::genConfig method.
 *
 * Consider the following example:
 *
 * @code{.cpp}
 *   class TestConfigPlugin : public ConfigPlugin {
 *    public:
 *     virtual std::pair<osquery::Status, std::string> genConfig() {
 *       std::string config;
 *       auto status = getMyConfig(config);
 *       return std::make_pair(status, config);
 *     }
 *   };
 *
 *   REGISTER(TestConfigPlugin, "config", "test");
 *  @endcode
 */
class ConfigPlugin : public Plugin {
 public:
  /**
   * @brief Virtual method which should implemented custom config retrieval
   *
   * ConfigPlugin::genConfig should be implemented by a subclasses of
   * ConfigPlugin which needs to retrieve config data in a custom way.
   *
   * @return a pair such that pair.first is an osquery::Status instance which
   * indicates the success or failure of config retrieval. If pair.first
   * indicates that config retrieval was successful, then the config data
   * should be returned in pair.second.
   */
  virtual Status genConfig(std::map<std::string, std::string>& config) = 0;
  Status call(const PluginRequest& request, PluginResponse& response);
};

/// Helper merged and parsed property tree.
typedef pt::ptree ConfigTree;

/**
 * @brief A pluggable configuration parser.
 *
 * An osquery config instance is populated from JSON using a ConfigPlugin.
 * That plugin may update the config data asynchronously and read from
 * several sources, as is the case with "filesystem" and reading multiple files.
 *
 * A ConfigParserPlugin will receive the merged configuration at osquery start
 * and the updated (still merged) config if any ConfigPlugin updates the
 * instance asynchronously. Each parser specifies a set of top-level JSON
 * keys to receive. The config instance will auto-merge the key values
 * from multiple sources if they are dictionaries or lists.
 *
 * If a top-level key is a dictionary, each source with the top-level key
 * will have its own dictionary keys merged and replaced based on the lexical
 * order of sources. For the "filesystem" config plugin this is the lexical
 * sorting of filenames. If the top-level key is a list, each source with the
 * top-level key will have its contents appended.
 *
 * Each config parser plugin will live alongside the config instance for the
 * life of the osquery process. The parser may perform actions at config load
 * and config update "time" as well as keep its own data members and be
 * accessible through the Config class API.
 */
class ConfigParserPlugin : public Plugin {
 protected:
  /**
   * @brief Return a list of top-level config keys to receive in updates.
   *
   * The ::update method will receive a map of these keys with a JSON-parsed
   * property tree of configuration data.
   *
   * @return A list of string top-level JSON keys.
   */
  virtual std::vector<std::string> keys() = 0;

  /**
   * @brief Receive a merged property tree for each top-level config key.
   *
   * Called when the Config instance is initially loaded with data from the
   * active config plugin and when it is updated via an async ConfigPlugin
   * update. Every config parser will receive a map of merged data for each key
   * they requested in keys().
   *
   * @param config A JSON-parsed property tree map.
   * @return Failure if the parser should no longer receive updates.
   */
  virtual Status update(const std::map<std::string, ConfigTree>& config) = 0;

 protected:
  /// Allow the config parser to keep some global state.
  pt::ptree data_;

 private:
  Status setUp();

 private:
  /// Config::update will call all appropriate parser updates.
  friend class Config;
  /// A config data instance implements a read/write lock around data_ access.
  friend class ConfigDataInstance;
};

/**
 * @brief Calculate a splayed integer based on a variable splay percentage
 *
 * The value of splayPercent must be between 1 and 100. If it's not, the
 * value of original will be returned.
 *
 * @param original The original value to be modified
 * @param splayPercent The percent in which to splay the original value by
 *
 * @return The modified version of original
 */
int splayValue(int original, int splayPercent);

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
}
