/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <cstdio>
#include <cstring>

#ifdef WIN32
#include <io.h>
#endif

#include <iostream>

#include <boost/algorithm/string/predicate.hpp>

#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/extensions.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/system.h>

#include "osquery/core/process.h"
#include "osquery/core/utils.h"
#include "osquery/core/watcher.h"
#include "osquery/devtools/devtools.h"
#include "osquery/dispatcher/distributed.h"
#include "osquery/dispatcher/io_service.h"
#include "osquery/dispatcher/scheduler.h"
#include "osquery/filesystem/fileops.h"
#include "osquery/main/main.h"
#include "osquery/sql/sqlite_util.h"

namespace fs = boost::filesystem;

namespace osquery {

SHELL_FLAG(int32,
           profile,
           0,
           "Enable profile mode when non-0, set number of iterations");

HIDDEN_FLAG(int32,
            profile_delay,
            0,
            "Sleep a number of seconds before and after the profiling");

CLI_FLAG(bool, install, false, "Install osqueryd as a service");

CLI_FLAG(bool, uninstall, false, "Uninstall osqueryd as a service");

DECLARE_bool(disable_caching);

const std::string kWatcherWorkerName{"osqueryd: worker"};

int profile(int argc, char* argv[]) {
  std::string query;
  if (!osquery::platformIsatty(stdin)) {
    std::getline(std::cin, query);
  } else if (argc < 2) {
    // No query input provided via stdin or as a positional argument.
    fprintf(stderr, "No query provided via stdin or args to profile...\n");
    return 2;
  } else {
    query = std::string(argv[1]);
  }

  if (osquery::FLAGS_profile_delay > 0) {
    osquery::sleepFor(osquery::FLAGS_profile_delay * 1000);
  }

  // Perform some duplication from Initializer with respect to database setup.
  osquery::RegistryFactory::get().setActive("database", "ephemeral");

  auto dbc = osquery::SQLiteDBManager::get();
  for (size_t i = 0; i < static_cast<size_t>(osquery::FLAGS_profile); ++i) {
    osquery::QueryData results;
    auto status = osquery::queryInternal(query, results, dbc);
    dbc->clearAffectedTables();
    if (!status) {
      fprintf(stderr,
              "Query failed (%d): %s\n",
              status.getCode(),
              status.what().c_str());
      return status.getCode();
    }
  }

  if (osquery::FLAGS_profile_delay > 0) {
    osquery::sleepFor(osquery::FLAGS_profile_delay * 1000);
  }

  return 0;
}

int startDaemon(Initializer& runner) {
  runner.start();

  // Conditionally begin the distributed query service
  auto s = startDistributed();
  if (!s.ok()) {
    VLOG(1) << "Not starting the distributed query service: " << s.toString();
  }

  // Begin the schedule runloop.
  startScheduler();

  // Finally wait for a signal / interrupt to shutdown.
  runner.waitForShutdown();
  return 0;
}

int startShell(osquery::Initializer& runner, int argc, char* argv[]) {
  // Check for shell-specific switches and positional arguments.
  if (argc > 1 || !osquery::platformIsatty(stdin) ||
      !osquery::FLAGS_A.empty() || !osquery::FLAGS_pack.empty() ||
      osquery::FLAGS_L || osquery::FLAGS_profile > 0) {
    // A query was set as a positional argument, via stdin, or profiling is on.
    osquery::FLAGS_disable_events = true;
    osquery::FLAGS_disable_caching = true;
    // The shell may have loaded table extensions, if not, disable the manager.
    if (!osquery::Watcher::get().hasManagedExtensions() &&
        Flag::isDefault("disable_extensions")) {
      osquery::FLAGS_disable_extensions = true;
    }
  }

  int retcode = 0;
  if (osquery::FLAGS_profile <= 0) {
    runner.start();

    // Virtual tables will be attached to the shell's in-memory SQLite DB.
    retcode = osquery::launchIntoShell(argc, argv);
    // Finally shutdown.
    runner.requestShutdown();
  } else {
    retcode = profile(argc, argv);
  }
  return retcode;
}

int startOsquery(int argc, char* argv[], std::function<void()> shutdown) {
  // Parse/apply flags, start registry, load logger/config plugins.
  osquery::Initializer runner(argc, argv, osquery::ToolType::SHELL_DAEMON);

  // Options for installing or uninstalling the osqueryd as a service
  if (FLAGS_install) {
    auto binPath = fs::system_complete(fs::path(argv[0]));
    if (!installService(binPath.string())) {
      LOG(ERROR) << "Unable to install the osqueryd service";
    }
    return 1;
  } else if (FLAGS_uninstall) {
    if (!uninstallService()) {
      LOG(ERROR) << "Unable to uninstall the osqueryd service";
    }
    return 1;
  }

  runner.installShutdown(shutdown);
  runner.initDaemon();

  // When a watchdog is used, the current daemon will fork/exec into a worker.
  // In either case the watcher may start optionally loaded extensions.
  runner.initWorkerWatcher(kWatcherWorkerName);

  // Begin adhoc io service thread.
  startIOService();

  if (runner.isDaemon()) {
    return startDaemon(runner);
  }
  return startShell(runner, argc, argv);
}
} // namespace osquery
