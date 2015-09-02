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

#include <osquery/core.h>
#include <osquery/logger.h>

#include "osquery/dispatcher/scheduler.h"

const std::string kWatcherWorkerName = "osqueryd: worker";

int main(int argc, char* argv[]) {
  osquery::Initializer runner(argc, argv, osquery::OSQUERY_TOOL_DAEMON);

  if (!runner.isWorker()) {
    runner.initDaemon();
  }

  // When a watchdog is used, the current daemon will fork/exec into a worker.
  // In either case the watcher may start optionally loaded extensions.
  runner.initWorkerWatcher(kWatcherWorkerName);

  // Start osquery work.
  runner.start();

  // Begin the schedule runloop.
  auto s = osquery::startScheduler();
  if (!s.ok()) {
    LOG(ERROR) << "Error starting scheduler: " << s.toString();
  }

  // Finally shutdown.
  runner.shutdown();

  return 0;
}
