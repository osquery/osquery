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
  std::map<std::string, std::vector<std::string> > yaraFiles;
  pt::ptree all_data;
};

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
   * @brief Get a map of all the files in the YARA JSON blob
   *
   *
   *
   * @return A map all the files in the JSON blob organized by category
   */
  static const std::map<std::string, std::vector<std::string> >& getYARAFiles();

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
  static Status checkConfig();

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
  static void mergeConfig(const std::string& source, ConfigData& conf);

 private:
  /**
   * @brief the private member that stores the raw osquery config data in a
   * native format
   */
  ConfigData data_;
  /// The raw JSON source map from the config plugin.
  std::map<std::string, std::string> raw_;

  /// The reader/writer config data mutex.
  boost::shared_mutex mutex_;

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
 * This class will request a read-only lock of the config's changable internal
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
  const std::map<std::string, ScheduledQuery> schedule() {
    return Config::getInstance().data_.schedule;
  }

  /// Helper accessor for Config::data_.options.
  const std::map<std::string, std::string>& options() {
    return Config::getInstance().data_.options;
  }

  /// Helper accessor for Config::data_.files.
  const std::map<std::string, std::vector<std::string> >& files() {
    return Config::getInstance().data_.files;
  }

  /// Helper accessor for Config::data_.yaraFiles.
  const std::map<std::string, std::vector<std::string> >& yaraFiles() {
    return Config::getInstance().data_.yaraFiles;
  }

  /// Helper accessor for Config::data_.all_data.
  const pt::ptree& data() { return Config::getInstance().data_.all_data; }

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
}
