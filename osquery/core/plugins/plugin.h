/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <map>
#include <string>
#include <vector>

#include <boost/noncopyable.hpp>

#include <osquery/core/sql/table_rows.h>
#include <osquery/utils/status/status.h>

namespace osquery {

/**
 * @brief The request part of a plugin (registry item's) call.
 *
 * To use a plugin use Registry::call with a request and response.
 * The request portion is usually simple and normally includes an "action"
 * key where the value is the action you want to perform on the plugin.
 * Refer to the registry's documentation for the actions supported by
 * each of its plugins.
 */
using PluginRequest = std::map<std::string, std::string>;

/**
 * @brief The response part of a plugin (registry item's) call.
 *
 * If a Registry::call succeeds it will fill in a PluginResponse.
 * This response is a vector of key value maps.
 */
using PluginResponse = std::vector<PluginRequest>;

class Plugin : private boost::noncopyable {
 public:
  virtual ~Plugin() = default;

 public:
  /// The plugin may perform some initialization, not required.
  virtual Status setUp() {
    return Status::success();
  }

  /// The plugin may perform some tear down, release, not required.
  virtual void tearDown() {}

  /// The plugin may react to configuration updates.
  virtual void configure() {}

  /// The plugin may publish route info (other than registry type and name).
  virtual PluginResponse routeInfo() const {
    return PluginResponse();
  }

  /**
   * @brief Plugins act by being called, using a request, returning a response.
   *
   * The plugin request is a thrift-serializable object. A response is optional
   * but the API for using a plugin's call is defined by the registry. In most
   * cases there are multiple supported call 'actions'. A registry type, or
   * the plugin class, will define the action key and supported actions.
   *
   * @param request A plugin request input, including optional action.
   * @param response A plugin response output.
   *
   * @return Status of the call, if the action was handled corrected.
   */
  virtual Status call(const PluginRequest& request,
                      PluginResponse& response) = 0;

  /// Allow the plugin to introspect into the registered name (for logging).
  virtual void setName(const std::string& name) final;

  /// Force call-sites to use #getName to access the plugin item's name.
  virtual const std::string& getName() const {
    return name_;
  }

 public:

  /**
   * @brief Bind this plugin to an external plugin reference.
   *
   * Allow a specialized plugin type to act when an external plugin is
   * registered (e.g., a TablePlugin will attach the table name).
   *
   * @param name The broadcasted name of the plugin.
   * @param info The routing info for the owning extension.
   */
  static Status addExternal(const std::string& name,
                            const PluginResponse& info) {
    (void)name;
    (void)info;
    return Status::success();
  }

  /// Allow a specialized plugin type to act when an external plugin is removed.
  static void removeExternal(const std::string& /*name*/) {}

 protected:
  /// Customized name for the plugin, usually set by the registry.
  std::string name_;
};

/// Helper definition for a shared pointer to a Plugin.
using PluginRef = std::shared_ptr<Plugin>;

/// Converts a TableRows object to a PluginResponse.
PluginResponse tableRowsToPluginResponse(const TableRows& rows);

} // namespace osquery
