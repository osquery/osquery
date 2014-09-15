// Copyright 2004-present Facebook. All Rights Reserved.

#include <boost/thread.hpp>

#include <glog/logging.h>

#include "osquery/config.h"
#include "osquery/config/plugin.h"
#include "osquery/core.h"
#include "osquery/logger/plugin.h"
#include "osquery/scheduler.h"

int main(int argc, char* argv[]) {
  osquery::initOsquery(argc, argv);

  LOG(INFO) << "Listing all plugins";

  LOG(INFO) << "Logger plugins:";
  for (const auto& it : REGISTERED_LOGGER_PLUGINS) {
    LOG(INFO) << "  - " << it.first;
  }

  LOG(INFO) << "Config plugins:";
  for (const auto& it : REGISTERED_CONFIG_PLUGINS) {
    LOG(INFO) << "  - " << it.first;
  }

  boost::thread scheduler_thread(osquery::initializeScheduler);

  scheduler_thread.join();

  return 0;
}
