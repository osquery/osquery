/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <syslog.h>
#include <time.h>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/events.h>
#include <osquery/flags.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry.h>

namespace osquery {

const std::string kDescription =
    "your operating system as a high-performance "
    "relational database";
const std::string kEpilog = "osquery project page <http://osquery.io>.";

FLAG(bool, config_check, false, "Check the format of an osquery config");

#ifndef __APPLE__
namespace osquery {
FLAG(bool, daemonize, false, "Run as daemon (osqueryd only)");
}
#endif

namespace fs = boost::filesystem;

void printUsage(const std::string& binary, int tool) {
  // Parse help options before gflags. Only display osquery-related options.
  fprintf(stdout, "osquery " OSQUERY_VERSION ", %s\n", kDescription.c_str());
  if (tool == OSQUERY_TOOL_SHELL) {
    // The shell allows a caller to run a single SQL statement and exit.
    fprintf(
        stdout, "Usage: %s [OPTION]... [SQL STATEMENT]\n\n", binary.c_str());
  } else {
    fprintf(stdout, "Usage: %s [OPTION]...\n\n", binary.c_str());
  }

  fprintf(stdout, "The following options control osquery");
  if (tool == OSQUERY_EXTENSION) {
    fprintf(stdout, " extensions");
  }
  fprintf(stdout, ".\n\n");

  // Print only the core/internal or extension flags.
  if (tool == OSQUERY_EXTENSION) {
    Flag::printFlags(false, true);
  } else {
    Flag::printFlags();
  }

  if (tool == OSQUERY_TOOL_SHELL) {
    // Print shell flags.
    fprintf(stdout, "\nThe following control the osquery shell.\n\n");
    Flag::printFlags(true);
  }

  fprintf(stdout, "\n%s\n", kEpilog.c_str());
}

void printConfigWarning() {
  std::cerr << "You are using default configurations for osqueryd for one or "
               "more of the following\n"
            << "flags: pidfile, db_path.\n\n"
            << "These options create files in /var/osquery but it looks like "
               "that path has not\n"
            << "been created. Please consider explicitly defining those "
               "options as a different \n"
            << "path. Additionally, review the \"using osqueryd\" wiki page:\n"
            << " - https://github.com/facebook/osquery/wiki/using-osqueryd\n\n";
}

void announce() {
  syslog(LOG_NOTICE, "osqueryd started [version=" OSQUERY_VERSION "]");
}

void initOsquery(int argc, char* argv[], int tool) {
  std::srand(time(nullptr));
  std::string binary(fs::path(std::string(argv[0])).filename().string());
  std::string first_arg = (argc > 1) ? std::string(argv[1]) : "";

  // osquery implements a custom help/usage output.
  if ((first_arg == "--help" || first_arg == "-h" || first_arg == "-help") &&
      tool != OSQUERY_TOOL_TEST) {
    printUsage(binary, tool);
    ::exit(0);
  }

// To change the default config plugin, compile osquery with
// -DOSQUERY_DEFAULT_CONFIG_PLUGIN=<new_default_plugin>
#ifdef OSQUERY_DEFAULT_CONFIG_PLUGIN
  FLAGS_config_plugin = STR(OSQUERY_DEFAULT_CONFIG_PLUGIN);
#endif

// To change the default logger plugin, compile osquery with
// -DOSQUERY_DEFAULT_LOGGER_PLUGIN=<new_default_plugin>
#ifdef OSQUERY_DEFAULT_LOGGER_PLUGIN
  FLAGS_logger_plugin = STR(OSQUERY_DEFAULT_LOGGER_PLUGIN);
#endif

  // Set version string from CMake build
  GFLAGS_NAMESPACE::SetVersionString(OSQUERY_VERSION);

  // Let gflags parse the non-help options/flags.
  GFLAGS_NAMESPACE::ParseCommandLineFlags(&argc, &argv, false);

  // Initialize the status and results logger.
  initStatusLogger(binary);
  VLOG(1) << "osquery initialized [version=" OSQUERY_VERSION "]";

  if (tool != OSQUERY_EXTENSION) {
    // Load the osquery config using the default/active config plugin.
    Config::getInstance().load();

    if (FLAGS_config_check) {
      // The initiator requested an initialization and config check.
      auto s = Config::checkConfig();
      if (!s.ok()) {
        std::cerr << "Error reading config: " << s.toString() << "\n";
      }
      // A configuration check exits the application.
      ::exit(s.getCode());
    }
  }

  // Run the setup for all non-lazy registries.
  Registry::setUp();
  // Initialize the status and result plugin logger.
  initLogger(binary);
}

void initOsqueryDaemon() {
#ifndef __APPLE__
  // OSX uses launchd to daemonize.
  if (osquery::FLAGS_daemonize) {
    if (daemon(0, 0) == -1) {
      ::exit(EXIT_FAILURE);
    }
  }
#endif

  // Print the version to SYSLOG.
  announce();

  // check if /var/osquery exists
  if ((Flag::isDefault("pidfile") || Flag::isDefault("db_path")) &&
      !isDirectory("/var/osquery")) {
    printConfigWarning();
  }

  // Create a process mutex around the daemon.
  auto pid_status = createPidFile();
  if (!pid_status.ok()) {
    LOG(ERROR) << "osqueryd initialize failed: " << pid_status.toString();
    ::exit(EXIT_FAILURE);
  }

  // Check the backing store by allocating and exitting on error.
  if (!DBHandle::checkDB()) {
    LOG(ERROR) << "osqueryd initialize failed: Could not create DB handle";
    ::exit(EXIT_FAILURE);
  }
}

void shutdownOsquery() {
  // End any event type run loops.
  EventFactory::end();

  // Hopefully release memory used by global string constructors in gflags.
  GFLAGS_NAMESPACE::ShutDownCommandLineFlags();
}
}
