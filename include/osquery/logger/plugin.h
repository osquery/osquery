// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <memory>

#include "osquery/registry.h"
#include "osquery/status.h"

namespace osquery {

class LoggerPlugin {
 public:
  virtual osquery::Status logString(const std::string& s) = 0;
  virtual ~LoggerPlugin() {}

 protected:
  LoggerPlugin() {};
};
}

DECLARE_REGISTRY(LoggerPlugins,
                 std::string,
                 std::shared_ptr<osquery::LoggerPlugin>)

#define REGISTERED_LOGGER_PLUGINS REGISTRY(LoggerPlugins)

#define REGISTER_LOGGER_PLUGIN(name, decorator) \
  REGISTER(LoggerPlugins, name, decorator)
