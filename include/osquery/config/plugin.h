// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <future>
#include <utility>

#include <osquery/registry.h>
#include <osquery/status.h>

namespace osquery {

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
 *   REGISTER_CONFIG_PLUGIN(
 *     "test", std::make_shared<osquery::TestConfigPlugin>());
 *  @endcode
 */
class ConfigPlugin {
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

  /// Virtual destructor
  virtual ~ConfigPlugin() {}
};
}

DECLARE_REGISTRY(ConfigPlugins,
                 std::string,
                 std::shared_ptr<osquery::ConfigPlugin>)

#define REGISTERED_CONFIG_PLUGINS REGISTRY(ConfigPlugins)

#define REGISTER_CONFIG_PLUGIN(name, decorator) \
  REGISTER(ConfigPlugins, name, decorator)
