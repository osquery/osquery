/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <stdio.h>

#include <osquery/core.h>
#include <osquery/extensions.h>

#include "osquery/core/watcher.h"
#include "osquery/devtools/devtools.h"

int main(int argc, char *argv[]) {
  // Parse/apply flags, start registry, load logger/config plugins.
  osquery::Initializer runner(argc, argv, osquery::OSQUERY_TOOL_SHELL);
  if (argc > 1 || !isatty(fileno(stdin)) || osquery::FLAGS_A.size() > 0 ||
      osquery::FLAGS_L) {
    // A query was set as a positional argument for via stdin.
    osquery::FLAGS_disable_events = true;
    // The shell may have loaded table extensions, if not, disable the manager.
    if (!osquery::Watcher::hasManagedExtensions()) {
      osquery::FLAGS_disable_extensions = true;
    }
  }

  runner.start();

  // Virtual tables will be attached to the shell's in-memory SQLite DB.
  int retcode = osquery::launchIntoShell(argc, argv);

  // Finally shutdown.
  runner.shutdown();
  return retcode;
}
