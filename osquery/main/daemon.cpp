/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/thread.hpp>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/events.h>
#include <osquery/logger.h>
#include <osquery/scheduler.h>

#include "osquery/core/watcher.h"

const std::string kWatcherWorkerName = "osqueryd-worker";

#ifndef __APPLE__
namespace osquery {
DEFINE_osquery_flag(bool, daemonize, false, "Run as daemon (osqueryd only).");
}
#endif

namespace osquery {
DEFINE_osquery_flag(bool,
                    config_check,
                    false,
                    "Check the format and accessibility of the daemon");

DEFINE_osquery_flag(bool,
                    disable_watchdog,
                    false,
                    "Do not use a userland watchdog process.");
}

int main(int argc, char* argv[]) {
  osquery::initOsquery(argc, argv, osquery::OSQUERY_TOOL_DAEMON);

  if (osquery::FLAGS_config_check) {
    auto s = osquery::Config::checkConfig();
    if (!s.ok()) {
      std::cerr << "Error reading config: " << s.toString() << "\n";
    }
    return s.getCode();
  }

#ifndef __APPLE__
  // OSX uses launchd to daemonize.
  if (osquery::FLAGS_daemonize) {
    if (daemon(0, 0) == -1) {
      ::exit(EXIT_FAILURE);
    }
  }
#endif

  auto pid_status = osquery::createPidFile();
  if (!pid_status.ok()) {
    LOG(ERROR) << "Could not start osqueryd: " << pid_status.toString();
    ::exit(EXIT_FAILURE);
  }

  try {
    osquery::DBHandle::getInstance();
  } catch (std::exception& e) {
    LOG(ERROR) << "osqueryd failed to start: " << e.what();
    ::exit(EXIT_FAILURE);
  }

  if (!osquery::FLAGS_disable_watchdog) {
    // When a watcher is used, the current watcher will fork into a worker.
    osquery::initWorkerWatcher(kWatcherWorkerName, argc, argv);
  }

  LOG(INFO) << "Listing all plugins";

  LOG(INFO) << "Logger plugins:";
  for (const auto& name : osquery::Registry::names("logger")) {
    LOG(INFO) << "  - " << name;
  }

  LOG(INFO) << "Config plugins:";
  for (const auto& name : osquery::Registry::names("config")) {
    LOG(INFO) << "  - " << name;
  }

  LOG(INFO) << "Event Publishers:";
  for (const auto& name : osquery::Registry::names("publisher")) {
    LOG(INFO) << "  - " << name;
  }

  LOG(INFO) << "Event Subscribers:";
  for (const auto& name : osquery::Registry::names("subscriber")) {
    LOG(INFO) << "  - " << name;
  }

  // Start event threads.
  osquery::EventFactory::delay();

  boost::thread scheduler_thread(osquery::initializeScheduler);
  scheduler_thread.join();

  // Finally shutdown.
  osquery::shutdownOsquery();

  return 0;
}
