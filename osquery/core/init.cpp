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
#include <osquery/extensions.h>
#include <osquery/flags.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry.h>

#include "osquery/core/watcher.h"

namespace osquery {

#define DESCRIPTION \
  "osquery %s, your OS as a high-performance relational database\n"
#define EPILOG "\nosquery project page <http://osquery.io>.\n"
#define OPTIONS \
  "\nosquery configuration options (set by config or CLI flags):\n\n"
#define OPTIONS_SHELL "\nosquery shell-only CLI flags:\n\n"
#define OPTIONS_CLI "osquery%s command line flags:\n\n"
#define USAGE "Usage: %s [OPTION]... %s\n\n"
#define CONFIG_ERROR                                                          \
  "You are using default configurations for osqueryd for one or more of the " \
  "following\n"                                                               \
  "flags: pidfile, db_path.\n\n"                                              \
  "These options create files in /var/osquery but it looks like that path "   \
  "has not\n"                                                                 \
  "been created. Please consider explicitly defining those "                  \
  "options as a different \n"                                                 \
  "path. Additionally, review the \"using osqueryd\" wiki page:\n"            \
  " - https://github.com/facebook/osquery/wiki/using-osqueryd\n\n";

CLI_FLAG(bool,
         config_check,
         false,
         "Check the format of an osquery config and exit");

#ifndef __APPLE__
CLI_FLAG(bool, daemonize, false, "Run as daemon (osqueryd only)");
#endif

namespace fs = boost::filesystem;

void printUsage(const std::string& binary, int tool) {
  // Parse help options before gflags. Only display osquery-related options.
  fprintf(stdout, DESCRIPTION, OSQUERY_VERSION);
  if (tool == OSQUERY_TOOL_SHELL) {
    // The shell allows a caller to run a single SQL statement and exit.
    fprintf(stdout, USAGE, binary.c_str(), "[SQL STATEMENT]");
  } else {
    fprintf(stdout, USAGE, binary.c_str(), "");
  }

  if (tool == OSQUERY_EXTENSION) {
    fprintf(stdout, OPTIONS_CLI, " extension");
    Flag::printFlags(false, true);
  } else {
    fprintf(stdout, OPTIONS_CLI, "");
    Flag::printFlags(false, false, true);
    fprintf(stdout, OPTIONS);
    Flag::printFlags();
  }

  if (tool == OSQUERY_TOOL_SHELL) {
    // Print shell flags.
    fprintf(stdout, OPTIONS_SHELL);
    Flag::printFlags(true);
  }

  fprintf(stdout, EPILOG);
}

Initializer::Initializer(int argc, char* argv[], int tool)
    : argc_(argc),
      argv_((char**)argv),
      tool_(tool),
      binary_(fs::path(std::string(argv[0])).filename().string()) {
  std::srand(time(nullptr));

  // osquery implements a custom help/usage output.
  std::string first_arg = (argc_ > 1) ? std::string(argv_[1]) : "";
  if ((first_arg == "--help" || first_arg == "-h" || first_arg == "-help") &&
      tool != OSQUERY_TOOL_TEST) {
    printUsage(binary_, tool_);
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
  GFLAGS_NAMESPACE::ParseCommandLineFlags(&argc_, &argv_, false);

  // If the caller is checking configuration, disable the watchdog/worker.
  if (FLAGS_config_check) {
    FLAGS_disable_watchdog = true;
  }

  // Initialize the status and results logger.
  initStatusLogger(binary_);
  VLOG(1) << "osquery initialized [version=" << OSQUERY_VERSION << "]";
}

void Initializer::initDaemon() {
#ifndef __APPLE__
  // OSX uses launchd to daemonize.
  if (osquery::FLAGS_daemonize) {
    if (daemon(0, 0) == -1) {
      ::exit(EXIT_FAILURE);
    }
  }
#endif

  // Print the version to SYSLOG.
  syslog(
      LOG_NOTICE, "%s started [version=%s]", binary_.c_str(), OSQUERY_VERSION);

  // check if /var/osquery exists
  if ((Flag::isDefault("pidfile") || Flag::isDefault("db_path")) &&
      !isDirectory("/var/osquery")) {
    std::cerr << CONFIG_ERROR
  }

  // Create a process mutex around the daemon.
  auto pid_status = createPidFile();
  if (!pid_status.ok()) {
    LOG(ERROR) << binary_ << " initialize failed: " << pid_status.toString();
    ::exit(EXIT_FAILURE);
  }
}

void Initializer::initWorkerWatcher(const std::string& name) {
  // The watcher will forever monitor and spawn additional workers.
  Watcher watcher(argc_, argv_);
  watcher.setWorkerName(name);

  if (isWorker()) {
    // Do not start watching/spawning if this process is a worker.
    watcher.initWorker();
  } else {
    do {
      if (!watcher.watch()) {
        // The watcher failed, create a worker.
        watcher.createWorker();
        watcher.resetCounters();
      }
    } while (watcher.ok());

    // Executation should never reach this point.
    ::exit(EXIT_FAILURE);
  }
}

bool Initializer::isWorker() { return (getenv("OSQUERYD_WORKER") != nullptr); }

void Initializer::start() {
  // Bind to an extensions socket and wait for registry additions.
  osquery::startExtensionManager();

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

  // Run the setup for all lazy registries (tables, SQL).
  Registry::setUp();

  // Check the backing store by allocating and exiting on error.
  if (!DBHandle::checkDB()) {
    LOG(ERROR) << binary_ << " initialize failed: Could not create DB handle";
    if (isWorker()) {
      ::exit(EXIT_CATASTROPHIC);
    } else {
      ::exit(EXIT_FAILURE);
    }
  }

  // Initialize the status and result plugin logger.
  initLogger(binary_);

  // Start event threads.
  osquery::attachEvents();
  osquery::EventFactory::delay();
}

void Initializer::shutdown() {
  // End any event type run loops.
  EventFactory::end();

  // Hopefully release memory used by global string constructors in gflags.
  GFLAGS_NAMESPACE::ShutDownCommandLineFlags();
}
}
