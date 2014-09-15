// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <future>
#include <utility>

#include "osquery/registry.h"
#include "osquery/status.h"

namespace osquery {

class ConfigPlugin {
 public:
  virtual std::pair<osquery::Status, std::string> genConfig() = 0;
  virtual ~ConfigPlugin() {}

 protected:
  ConfigPlugin() {};
};
}

DECLARE_REGISTRY(ConfigPlugins,
                 std::string,
                 std::shared_ptr<osquery::ConfigPlugin>)

#define REGISTERED_CONFIG_PLUGINS REGISTRY(ConfigPlugins)

#define REGISTER_CONFIG_PLUGIN(name, decorator) \
  REGISTER(ConfigPlugins, name, decorator)
