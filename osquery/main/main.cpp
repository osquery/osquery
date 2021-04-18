/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#ifdef WIN32
#include <io.h>
#endif

#include <iostream>

#include <boost/algorithm/string/predicate.hpp>

#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/core/shutdown.h>
#include <osquery/core/system.h>
#include <osquery/core/watcher.h>
#include <osquery/database/database.h>
#include <osquery/devtools/devtools.h>
#include <osquery/dispatcher/distributed_runner.h>
#include <osquery/dispatcher/scheduler.h>
#include <osquery/extensions/extensions.h>
#include <osquery/filesystem/fileops.h>
#include <osquery/logger/logger.h>
#include <osquery/main/main.h>
#include <osquery/process/process.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sqlite_util.h>

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
    std::cerr << "No query provided via stdin or args to profile..."
              << std::endl;
    return 2;
  } else {
    query = std::string(argv[1]);
  }

  if (osquery::FLAGS_profile_delay > 0) {
    osquery::sleepFor(osquery::FLAGS_profile_delay * 1000);
  }

  // Perform some duplication from Initializer with respect to database setup.
  osquery::setDatabaseAllowOpen();
  osquery::RegistryFactory::get().setActive("database", "ephemeral");

  auto dbc = osquery::SQLiteDBManager::get();
  for (size_t i = 0; i < static_cast<size_t>(osquery::FLAGS_profile); ++i) {
    osquery::QueryData results;
    auto status = osquery::queryInternal(query, results, dbc);
    dbc->clearAffectedTables();
    if (!status) {
      std::cerr << "Query failed (" << status.getCode()
                << "): " << status.what() << std::endl;
      return status.getCode();
    }
  }

  if (osquery::FLAGS_profile_delay > 0) {
    osquery::sleepFor(osquery::FLAGS_profile_delay * 1000);
  }

  return 0;
}

void startDaemon(Initializer& runner) {
  runner.start();

  if (!shutdownRequested()) {
    // Conditionally begin the distributed query service
    auto s = startDistributed();
    if (!s.ok()) {
      VLOG(1) << "Not starting the distributed query service: " << s.toString();
    }

    // Begin the schedule runloop.
    startScheduler();
  }

  runner.waitForShutdown();
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
    if (!osquery::Watcher::hasManagedExtensions() &&
        Flag::isDefault("disable_extensions")) {
      osquery::FLAGS_disable_extensions = true;
    }
  }

  int retcode = 0;
  if (osquery::FLAGS_profile <= 0) {
    runner.start();
    if (shutdownRequested()) {
      // Something in the initialization errored or requested a shutown.
      runner.waitForShutdown();
      retcode = getShutdownExitCode();
    } else {
      // Virtual tables will be attached to the shell's in-memory SQLite DB.
      retcode = osquery::launchIntoShell(argc, argv);
    }
  } else {
    retcode = profile(argc, argv);
  }
  return retcode;
}

int startOsquery(int argc, char* argv[]) {
  // Parse/apply flags, start registry, load logger/config plugins.
  osquery::Initializer runner(argc, argv, osquery::ToolType::SHELL_DAEMON);

  // Options for installing or uninstalling the osqueryd as a service
  if (FLAGS_install && FLAGS_uninstall) {
    LOG(ERROR) << "osqueryd service install and uninstall can not be "
                  "requested together";
    return 1;
  }

  if (FLAGS_install) {
    auto binPath = fs::system_complete(fs::path(argv[0]));
    // "Wrap" the binPath in the event it contains spaces
    if (installService("\"" + binPath.string() + "\"")) {
      LOG(INFO) << "osqueryd service was installed successfully.";
      return 0;
    } else {
      LOG(ERROR) << "Unable to install the osqueryd service";
      return 1;
    }
  } else if (FLAGS_uninstall) {
    if (uninstallService()) {
      LOG(INFO) << "osqueryd service was uninstalled successfully.";
      return 0;
    } else {
      LOG(ERROR) << "Unable to uninstall the osqueryd service";
      return 1;
    }
  }

  int retcode = 0;
  runner.initDaemon();

  // When a watchdog is used, the current daemon will fork/exec into a worker.
  // In either case the watcher may start optionally loaded extensions.
  runner.initWorkerWatcher(kWatcherWorkerName);

  // Only worker processes should start a daemon or shell.
  if (!runner.isWatcher()) {
    if (isDaemon()) {
      startDaemon(runner);
    } else {
      retcode = startShell(runner, argc, argv);
    }
  }

  return runner.shutdown(retcode);
}
} // namespace osquery
