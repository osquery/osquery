// Copyright 2004-present Facebook. All Rights Reserved.

#include <glog/logging.h>

#include "osquery/config.h"
#include "osquery/config/plugin.h"
#include "osquery/core.h"
#include "osquery/logger.h"
#include "osquery/logger/plugin.h"
#include "osquery/registry.h"

int main(int argc, char* argv[]) {
  osquery::core::initOsquery(argc, argv);

  LOG(INFO) << "Listing all plugins";

  LOG(INFO) << "Logger plugins:";
  for (const auto& it : REGISTERED_LOGGER_PLUGINS) {
    LOG(INFO) << "  - " << it.first;
  }

  LOG(INFO) << "Config plugins:";
  for (const auto& it : REGISTERED_CONFIG_PLUGINS) {
    LOG(INFO) << "  - " << it.first;
  }

  return 0;
}
