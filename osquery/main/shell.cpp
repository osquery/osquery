/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <stdio.h>
#include <string.h>

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
#include <osquery/system.h>

#include "osquery/core/process.h"
#include "osquery/core/utils.h"
#include "osquery/core/watcher.h"
#include "osquery/devtools/devtools.h"
#include "osquery/filesystem/fileops.h"
#include "osquery/sql/sqlite_util.h"

namespace osquery {

SHELL_FLAG(int32,
           profile,
           0,
           "Enable profile mode when non-0, set number of iterations");
HIDDEN_FLAG(int32,
            profile_delay,
            0,
            "Sleep a number of seconds before and after the profiling");

DECLARE_bool(disable_caching);
}

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
  osquery::DatabasePlugin::setAllowOpen(true);
  osquery::RegistryFactory::get().setActive("database", "ephemeral");

  auto dbc = osquery::SQLiteDBManager::get();
  for (size_t i = 0; i < static_cast<size_t>(osquery::FLAGS_profile); ++i) {
    osquery::QueryData results;
    auto status = osquery::queryInternal(query, results, dbc->db());
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

int main(int argc, char* argv[]) {
  // Parse/apply flags, start registry, load logger/config plugins.
  osquery::Initializer runner(argc, argv, osquery::ToolType::SHELL);

  // The shell will not use a worker process.
  // It will initialize a watcher thread for potential auto-loaded extensions.
  runner.initWorkerWatcher();

  // Check for shell-specific switches and positional arguments.
  if (argc > 1 || !osquery::platformIsatty(stdin) ||
      osquery::FLAGS_A.size() > 0 || osquery::FLAGS_pack.size() > 0 ||
      osquery::FLAGS_L || osquery::FLAGS_profile > 0) {
    // A query was set as a positional argument, via stdin, or profiling is on.
    osquery::FLAGS_disable_events = true;
    osquery::FLAGS_disable_caching = true;
    // The shell may have loaded table extensions, if not, disable the manager.
    if (!osquery::Watcher::get().hasManagedExtensions()) {
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
