/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include "config.h"

#include <osquery/config/config_plugin.h>
#include <osquery/flags.h>
#include <osquery/registry.h>

namespace osquery {

/**
 * @brief Config plugin registry.
 *
 * This creates an osquery registry for "config" which may implement
 * ConfigPlugin. A ConfigPlugin's call API should make use of a genConfig
 * after reading JSON data in the plugin implementation.
 */
CREATE_REGISTRY(ConfigPlugin, "config");

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
    std::map<std::string, std::string> config;
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
} // namespace osquery
