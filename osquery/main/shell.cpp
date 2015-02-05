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
#include <osquery/events.h>
#include <osquery/extensions.h>
#include <osquery/logger.h>

int main(int argc, char *argv[]) {
  if (boost::filesystem::create_directory("/tmp/osquery")) {
    osquery::FLAGS_db_path = "/tmp/osquery/shell.db";
    osquery::FLAGS_extensions_socket = "/tmp/osquery/shell.em";
    FLAGS_log_dir = "/tmp/osquery/";
  }

  // Parse/apply flags, start registry, load logger/config plugins.
  osquery::initOsquery(argc, argv, osquery::OSQUERY_TOOL_SHELL);

  // Start event threads.
  osquery::EventFactory::delay();
  osquery::startExtensionManager();

  // Virtual tables will be attached to the shell's in-memory SQLite DB.
  int retcode = osquery::launchIntoShell(argc, argv);

  // Finally shutdown.
  osquery::shutdownOsquery();
  return retcode;
}
