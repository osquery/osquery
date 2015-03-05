/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/filesystem.hpp>

#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/devtools.h>
#include <osquery/extensions.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

const std::string kShellTemp = "/tmp/osquery";

int main(int argc, char *argv[]) {
  // The shell is transient, rewrite config-loaded paths.
  if (osquery::pathExists(kShellTemp).ok() ||
      boost::filesystem::create_directory(kShellTemp)) {
    osquery::FLAGS_database_path = kShellTemp + "/shell.db";
    osquery::FLAGS_extensions_socket = kShellTemp + "/shell.em";
    osquery::FLAGS_disable_logging = true;
  }

  // Parse/apply flags, start registry, load logger/config plugins.
  osquery::Initializer runner(argc, argv, osquery::OSQUERY_TOOL_SHELL);
  runner.start();

  // Virtual tables will be attached to the shell's in-memory SQLite DB.
  int retcode = osquery::launchIntoShell(argc, argv);

  // Finally shutdown.
  runner.shutdown();
  return retcode;
}
