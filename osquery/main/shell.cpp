/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/core.h>

#include "osquery/devtools/devtools.h"

int main(int argc, char *argv[]) {
  // Parse/apply flags, start registry, load logger/config plugins.
  osquery::Initializer runner(argc, argv, osquery::OSQUERY_TOOL_SHELL);
  runner.start();

  // Virtual tables will be attached to the shell's in-memory SQLite DB.
  int retcode = osquery::launchIntoShell(argc, argv);

  // Finally shutdown.
  runner.shutdown();
  return retcode;
}
