/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/plugins/plugin.h>

#include <map>
#include <string>

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
 *     virtual Status genConfig(std::map<std::string, std::string>& config) {
 *       config["my_source"] = "{}";
 *       return Status::success();
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
   * @param config The output ConfigSourceMap, a map of JSON to source names.
   *
   * @return A failure status will prevent the source map from merging.
   */
  virtual Status genConfig(std::map<std::string, std::string>& config) = 0;

  /**
   * @brief Virtual method which could implement custom query pack retrieval
   *
   * The default config syntax for query packs is like the following:
   *
   * @code
   *   {
   *     "packs": {
   *       "foo": {
   *         "version": "1.5.0",
   *         "platform:" "any",
   *         "queries": {
   *           // ...
   *         }
   *       }
   *     }
   *   }
   * @endcode
   *
   * Alternatively, you can define packs like the following as well:
   *
   * @code
   *   {
   *     "packs": {
   *       "foo": "/var/osquery/packs/foo.json",
   *       "bar": "/var/osquery/packs/bar.json"
   *     }
   *   }
   * @endcode
   *
   * If you defined the "value" of your pack as a string instead of an inline
   * data structure, then osquery will pass the responsibility of retrieving
   * the pack to the active config plugin. In the above example, it seems
   * obvious that the value is a local file path. Alternatively, if the
   * filesystem config plugin wasn't being used, the string could be a remote
   * URL, etc.
   *
   * genPack is not a pure virtual, so you don't have to define it if you don't
   * want to use the shortened query pack syntax. The default implementation
   * returns a failed status.
   *
   * @param name is the name of the query pack
   * @param value is the string based value that was provided with the pack
   * @param pack should be populated with the string JSON pack content
   *
   * @return a Status instance indicating the success or failure of the call
   */
  virtual Status genPack(const std::string& name,
                         const std::string& value,
                         std::string& pack);

  /// Main entrypoint for config plugin requests
  Status call(const PluginRequest& request, PluginResponse& response) override;
};
} // namespace osquery
