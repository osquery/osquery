// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef OSQUERY_CONFIG_PLUGIN_H
#define OSQUERY_CONFIG_PLUGIN_H

#include <future>
#include <utility>

#include "osquery/registry.h"
#include "osquery/core/status.h"

namespace osquery { namespace config {

class ConfigPlugin {
public:
  virtual std::pair<osquery::core::Status, std::string> genConfig() {
    return std::make_pair(osquery::core::Status(1, "Not implemented"), "");
  }
  virtual ~ConfigPlugin() {}
protected:
  ConfigPlugin() {};
};

}}

DECLARE_REGISTRY(
  ConfigPlugins,
  std::string,
  std::shared_ptr<osquery::config::ConfigPlugin>)

#define REGISTERED_CONFIG_PLUGINS REGISTRY(ConfigPlugins)

#define REGISTER_CONFIG_PLUGIN(name, decorator) \
  REGISTER(ConfigPlugins, name, decorator)

#endif
