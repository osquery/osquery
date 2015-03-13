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

#include <osquery/flags.h>
#include <osquery/registry.h>
#include <osquery/scheduler.h>
#include <osquery/status.h>

namespace osquery {

/// The builder or invoker may change the default config plugin.
DECLARE_string(config_plugin);

/**
 * @brief A native representation of osquery configuration data.
 *
 * When you use osquery::Config::getInstance(), you are getting a singleton
 * handle to interact with the data stored in an instance of this struct.
 */
struct OsqueryConfig {
  /// A vector of all of the queries that are scheduled to execute.
  std::vector<OsqueryScheduledQuery> scheduledQueries;
  std::map<std::string, std::string> options;
  std::map<std::string, std::vector<std::string> > eventFiles;
};

/**
 * @brief A string which represents the default consfig retriever.
 *
 * The config plugin that you use to define your config retriever can be
 * defined via a command-line flag, however, if you don't define a config
 * plugin to use via the command-line, then the config retriever which is
 * represented by the string stored in kDefaultConfigRetriever will be used.
 */
extern const std::string kDefaultConfigRetriever;

/**
 * @brief A singleton that exposes accessors to osquery's configuration data.
 *
 * osquery has two types on configurations. Things that don't change during
 * the execution of the process should be configured as command-line
 * arguments. Things that can change during the lifetime of program execution
 * should be defined using the osquery::config::Config class and the pluggable
 * plugin interface that is included with it.
 */
class Config {
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
   * @brief Get a vector of all scheduled queries.
   *
   * @code{.cpp}
   *   auto config = osquery::config::Config::getInstance();
   *   for (const auto& q : config->getScheduledQueries()) {
   *     LOG(INFO) << "name:     " << q.name;
   *     LOG(INFO) << "interval: " << q.interval;
   *   }
   * @endcode
   *
   * @return a vector of OsqueryScheduledQuery's which represent the queries
   * that are to be executed
   */
  static std::vector<OsqueryScheduledQuery> getScheduledQueries();

  /**
   * @brief Get a map of all the files in the intel JSON blob
   *
   *
   *
   * @return A map all the files in the JSON blob organized by category
   */
  static std::map<std::string, std::vector<std::string> >& getWatchedFiles();

  /**
   * @brief Calculate the has of the osquery config
   *
   * @return The MD5 of the osquery config
   */
  static Status getMD5(std::string& hashString);

  /**
   * @brief Check to ensure that the config is accessible and properly
   * formatted
   *
   * @return an instance of osquery::Status, indicating the success or failure
   * of the operation.
   */
  static osquery::Status checkConfig();
 private:
  /**
   * @brief Default constructor.
   *
   * Since instances of Config should only be created via getInstance(),
   * Config's constructor is private
   */
  Config() {}
  ~Config(){}
  Config(Config const&);
  void operator=(Config const&);


  /**
   * @brief Uses the specified config retriever to populate a config struct.
   *
   * Internally, genConfig checks to see if there was a config retriever
   * specified on the command-line. If there was, it checks to see if that
   * config retriever actually exists. If it does, it gets used to generate
   * configuration data. If it does not, an error is logged.
   *
   * If no config retriever was specified, the config retriever represented by
   * kDefaultConfigRetriever is used.
   *
   * @param conf a reference to a struct which will be populated by the config
   * retriever in use.
   *
   * @return an instance of osquery::Status, indicating the success or failure
   * of the operation.
   */
  static osquery::Status genConfig(OsqueryConfig& conf);

  /**
   * @brief Uses the specified config retriever to populate a string with the
   * config JSON.
   *
   * Internally, genConfig checks to see if there was a config retriever
   * specified on the command-line. If there was, it checks to see if that
   * config retriever actually exists. If it does, it gets used to generate
   * configuration data. If it does not, an error is logged.
   *
   * If no config retriever was specified, the config retriever represented by
   * kDefaultConfigRetriever is used.
   *
   * @param conf a reference to a string which will be populated by the config
   * retriever in use.
   *
   * @return an instance of osquery::Status, indicating the success or failure
   * of the operation.
   */
  static osquery::Status genConfig(std::string& conf);

  /// Prevent ConfigPlugins from implementing setUp.
  osquery::Status setUp() { return Status(0, "Not used"); }

 private:
  /**
   * @brief the private member that stores the raw osquery config data in a
   * native format
   */
  OsqueryConfig cfg_;
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
  virtual std::pair<osquery::Status, std::string> genConfig() = 0;
  Status call(const PluginRequest& request, PluginResponse& response);
};

/**
 * @brief Config plugin registry.
 *
 * This creates an osquery registry for "config" which may implement
 * ConfigPlugin. A ConfigPlugin's call API should make use of a genConfig
 * after reading JSON data in the plugin implementation.
 */
CREATE_REGISTRY(ConfigPlugin, "config");
}
