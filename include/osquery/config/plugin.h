// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <future>
#include <utility>

#include "osquery/registry.h"
#include "osquery/status.h"

namespace osquery {
namespace config {

class ConfigPlugin {
 public:
  virtual std::pair<osquery::Status, std::string> genConfig() {
    return std::make_pair(osquery::Status(1, "Not implemented"), "");
  }
  virtual ~ConfigPlugin() {}

 protected:
  ConfigPlugin() {};
};
}
}

DECLARE_REGISTRY(ConfigPlugins,
                 std::string,
                 std::shared_ptr<osquery::config::ConfigPlugin>)

#define REGISTERED_CONFIG_PLUGINS REGISTRY(ConfigPlugins)

#define REGISTER_CONFIG_PLUGIN(name, decorator) \
  REGISTER(ConfigPlugins, name, decorator)
