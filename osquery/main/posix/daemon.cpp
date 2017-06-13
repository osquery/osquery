/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/core.h>
#include <osquery/system.h>

const std::string kWatcherWorkerName = "osqueryd: worker";

int main(int argc, char* argv[]) {
  osquery::Initializer runner(argc, argv, osquery::ToolType::DAEMON);

  if (!runner.isWorker()) {
    runner.initDaemon();
  }

  // When a watchdog is used, the current daemon will fork/exec into a worker.
  // In either case the watcher may start optionally loaded extensions.
  runner.initWorkerWatcher(kWatcherWorkerName);

  // Start osquery work.
  runner.runDaemon();

  // Finally wait for a signal / interrupt to shutdown.
  runner.waitForShutdown();
  return 0;
}
