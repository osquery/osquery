/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <chrono>
#include <csignal>
#include <random>

#include <syslog.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <boost/algorithm/string/trim.hpp>
#include <boost/filesystem.hpp>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/events.h>
#include <osquery/extensions.h>
#include <osquery/flags.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry.h>

#include "osquery/core/watcher.h"
#include "osquery/database/db_handle.h"

#if defined(__linux__) || defined(__FreeBSD__)
#include <sys/resource.h>
#endif

#ifdef __linux__
#include <sys/syscall.h>

/*
 * These are the io priority groups as implemented by CFQ. RT is the realtime
 * class, it always gets premium service. BE is the best-effort scheduling
 * class, the default for any process. IDLE is the idle scheduling class, it
 * is only served when no one else is using the disk.
 */
enum {
  IOPRIO_CLASS_NONE,
  IOPRIO_CLASS_RT,
  IOPRIO_CLASS_BE,
  IOPRIO_CLASS_IDLE,
};

/*
 * 8 best effort priority levels are supported
 */
#define IOPRIO_BE_NR  (8)

enum {
  IOPRIO_WHO_PROCESS = 1,
  IOPRIO_WHO_PGRP,
  IOPRIO_WHO_USER,
};
#endif

#define DESCRIPTION \
  "osquery %s, your OS as a high-performance relational database\n"
#define EPILOG "\nosquery project page <https://osquery.io>.\n"
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
  " - https://osquery.readthedocs.org/en/latest/introduction/using-osqueryd/" \
  "\n\n";

/// Seconds to alarm and quit for non-responsive event loops.
#define SIGNAL_ALARM_TIMEOUT 4

namespace fs = boost::filesystem;

namespace {
extern "C" {
static inline bool hasWorkerVariable() {
  return (getenv("OSQUERY_WORKER") != nullptr);
}

volatile std::sig_atomic_t kHandledSignal{0};

void signalHandler(int signal) {
  // Inform exit status of main threads blocked by service joins.
  if (kHandledSignal == 0) {
    kHandledSignal = signal;
  }

  // Handle signals based on a tri-state (worker, watcher, neither).
  pid_t worker_pid = osquery::Watcher::getWorker();
  bool is_watcher = worker_pid > 0;
  if (signal == SIGHUP) {
    if (!is_watcher || hasWorkerVariable()) {
      // Reload configuration.
    }
  } else if (signal == SIGTERM || signal == SIGINT || signal == SIGABRT) {
    // Time to stop, set an upper bound time constraint on how long threads
    // have to terminate (join). Publishers may be in 20ms or similar sleeps.
    alarm(SIGNAL_ALARM_TIMEOUT);

    // Restore the default signal handler.
    std::signal(signal, SIG_DFL);

    // The watcher waits for the worker to die.
    if (is_watcher) {
      // Bind the fate of the worker to this watcher.
      osquery::Watcher::bindFates();
    } else {
      // Otherwise the worker or non-watched process joins.
      osquery::EventFactory::end(true);
      // Re-raise the handled signal, which has since been restored to default.
      raise(signal);
    }
  } else if (signal == SIGALRM) {
    // Restore the default signal handler for SIGALRM.
    std::signal(SIGALRM, SIG_DFL);

    // Took too long to stop.
    VLOG(1) << "Cannot stop event publisher threads";
    raise((kHandledSignal != 0) ? kHandledSignal : SIGALRM);
  }

  if (is_watcher) {
    // The signal should be proliferated through the process group.
    // Otherwise the watcher could 'forward' the signal to workers and
    // managed extension processes.
  }
}
}
}

namespace osquery {

typedef std::chrono::high_resolution_clock chrono_clock;

CLI_FLAG(bool,
         config_check,
         false,
         "Check the format of an osquery config and exit");

#ifndef __APPLE__
CLI_FLAG(bool, daemonize, false, "Run as daemon (osqueryd only)");
#endif

DECLARE_string(distributed_plugin);
DECLARE_bool(disable_distributed);

ToolType kToolType = OSQUERY_TOOL_UNKNOWN;

void printUsage(const std::string& binary, int tool) {
  // Parse help options before gflags. Only display osquery-related options.
  fprintf(stdout, DESCRIPTION, kVersion.c_str());
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

Initializer::Initializer(int& argc, char**& argv, ToolType tool)
    : argc_(&argc),
      argv_(&argv),
      tool_(tool),
      binary_(fs::path(std::string(argv[0])).filename().string()) {
  std::srand(chrono_clock::now().time_since_epoch().count());

  // Handled boost filesystem locale problems fixes in 1.56.
  // See issue #1559 for the discussion and upstream boost patch.
  try {
    boost::filesystem::path::codecvt();
  } catch(std::runtime_error &e) {
    setenv("LC_ALL", "C", 1);
  }

  // osquery implements a custom help/usage output.
  for (int i = 1; i < *argc_; i++) {
    auto help = std::string((*argv_)[i]);
    if ((help == "--help" || help == "-help" || help == "--h" ||
         help == "-h") &&
        tool != OSQUERY_TOOL_TEST) {
      printUsage(binary_, tool_);
      ::exit(0);
    }
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
  GFLAGS_NAMESPACE::SetVersionString(kVersion.c_str());

  // Let gflags parse the non-help options/flags.
  GFLAGS_NAMESPACE::ParseCommandLineFlags(
      argc_, argv_, (tool == OSQUERY_TOOL_SHELL));

  // Set the tool type to allow runtime decisions based on daemon, shell, etc.
  kToolType = tool;
  if (tool == OSQUERY_TOOL_SHELL) {
    // The shell is transient, rewrite config-loaded paths.
    FLAGS_disable_logging = true;
    // Get the caller's home dir for temporary storage/state management.
    auto homedir = osqueryHomeDirectory();
    if (osquery::pathExists(homedir).ok() ||
        boost::filesystem::create_directory(homedir)) {
      // Only apply user/shell-specific paths if not overridden by CLI flag.
      if (Flag::isDefault("database_path")) {
        osquery::FLAGS_database_path = homedir + "/shell.db";
      }
      if (Flag::isDefault("extensions_socket")) {
        osquery::FLAGS_extensions_socket = homedir + "/shell.em";
      }
    }
  }

  // All tools handle the same set of signals.
  // If a daemon process is a watchdog the signal is passed to the worker,
  // unless the worker has not yet started.
  std::signal(SIGTERM, signalHandler);
  std::signal(SIGABRT, signalHandler);
  std::signal(SIGINT, signalHandler);
  std::signal(SIGHUP, signalHandler);
  std::signal(SIGALRM, signalHandler);

  // If the caller is checking configuration, disable the watchdog/worker.
  if (FLAGS_config_check) {
    FLAGS_disable_watchdog = true;
  }

  // Initialize the status and results logger.
  initStatusLogger(binary_);
  if (tool != OSQUERY_EXTENSION) {
    if (isWorker()) {
      VLOG(1) << "osquery worker initialized [watcher=" << getppid() << "]";
    } else {
      VLOG(1) << "osquery initialized [version=" << kVersion << "]";
    }
  } else {
    VLOG(1) << "osquery extension initialized [sdk=" << kSDKVersion << "]";
  }
}

void Initializer::initDaemon() {
  if (FLAGS_config_check) {
    // No need to daemonize, emit log lines, or create process mutexes.
    return;
  }

#ifndef __APPLE__
  // OS X uses launchd to daemonize.
  if (osquery::FLAGS_daemonize) {
    if (daemon(0, 0) == -1) {
      ::exit(EXIT_FAILURE);
    }
  }
#endif

  // Print the version to SYSLOG.
  syslog(
      LOG_NOTICE, "%s started [version=%s]", binary_.c_str(), kVersion.c_str());

  // Check if /var/osquery exists
  if ((Flag::isDefault("pidfile") || Flag::isDefault("database_path")) &&
      !isDirectory("/var/osquery")) {
    std::cerr << CONFIG_ERROR;
  }

  // Create a process mutex around the daemon.
  auto pid_status = createPidFile();
  if (!pid_status.ok()) {
    LOG(ERROR) << binary_ << " initialize failed: " << pid_status.toString();
    ::exit(EXIT_FAILURE);
  }

  // Nice ourselves if using a watchdog and the level is not too permissive.
  if (!FLAGS_disable_watchdog &&
      FLAGS_watchdog_level >= WATCHDOG_LEVEL_DEFAULT &&
      FLAGS_watchdog_level != WATCHDOG_LEVEL_DEBUG) {
    // Set CPU scheduling I/O limits.
    setpriority(PRIO_PGRP, 0, 10);
#ifdef __linux__
    // Using: ioprio_set(IOPRIO_WHO_PGRP, 0, IOPRIO_CLASS_IDLE);
    syscall(SYS_ioprio_set, IOPRIO_WHO_PGRP, 0, IOPRIO_CLASS_IDLE);
#elif defined(__APPLE__)
    setiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_PROCESS, IOPOL_THROTTLE);
#endif
  }
}

void Initializer::initWatcher() {
  // The watcher takes a list of paths to autoload extensions from.
  osquery::loadExtensions();

  // Add a watcher service thread to start/watch an optional worker and set
  // of optional extensions in the autoload paths.
  if (Watcher::hasManagedExtensions() || !FLAGS_disable_watchdog) {
    Dispatcher::addService(std::make_shared<WatcherRunner>(
        *argc_, *argv_, !FLAGS_disable_watchdog));
  }

  // If there are no autoloaded extensions, the watcher service will end,
  // otherwise it will continue as a background thread and respawn them.
  // If the watcher is also a worker watchdog it will do nothing but monitor
  // the extensions and worker process.
  if (!FLAGS_disable_watchdog) {
    Dispatcher::joinServices();
    // Execution should only reach this point if a signal was handled by the
    // worker and watcher.
    ::exit((kHandledSignal > 0) ? 128 + kHandledSignal : EXIT_FAILURE);
  }
}

void Initializer::initWorker(const std::string& name) {
  // Clear worker's arguments.
  size_t name_size = strlen((*argv_)[0]);
  auto original_name = std::string((*argv_)[0]);
  for (int i = 0; i < *argc_; i++) {
    if ((*argv_)[i] != nullptr) {
      memset((*argv_)[i], ' ', strlen((*argv_)[i]));
    }
  }

  // Set the worker's process name.
  if (name.size() < name_size) {
    std::copy(name.begin(), name.end(), (*argv_)[0]);
    (*argv_)[0][name.size()] = '\0';
  } else {
    std::copy(original_name.begin(), original_name.end(), (*argv_)[0]);
    (*argv_)[0][original_name.size()] = '\0';
  }

  // Start a watcher watcher thread to exit the process if the watcher exits.
  Dispatcher::addService(std::make_shared<WatcherWatcherRunner>(getppid()));
}

void Initializer::initWorkerWatcher(const std::string& name) {
  if (isWorker()) {
    initWorker(name);
  } else {
    // The watcher will forever monitor and spawn additional workers.
    initWatcher();
  }
}

bool Initializer::isWorker() { return hasWorkerVariable(); }

void Initializer::initActivePlugin(const std::string& type,
                                   const std::string& name) {
  // Use a delay, meaning the amount of milliseconds waited for extensions.
  size_t delay = 0;
  // The timeout is the maximum microseconds in seconds to wait for extensions.
  size_t timeout = atoi(FLAGS_extensions_timeout.c_str()) * 1000000;
  if (timeout < kExtensionInitializeLatencyUS * 10) {
    timeout = kExtensionInitializeLatencyUS * 10;
  }
  while (!Registry::setActive(type, name)) {
    if (!Watcher::hasManagedExtensions() || delay > timeout) {
      LOG(ERROR) << "Active " << type << " plugin not found: " << name;
      ::exit(EXIT_CATASTROPHIC);
    }
    delay += kExtensionInitializeLatencyUS;
    ::usleep(kExtensionInitializeLatencyUS);
  }
}

void Initializer::start() {
  // Load registry/extension modules before extensions.
  osquery::loadModules();

  // Pre-extension manager initialization options checking.
  if (FLAGS_config_check && !Watcher::hasManagedExtensions()) {
    FLAGS_disable_extensions = true;
  }

  // Check the backing store by allocating and exiting on error.
  if (!DBHandle::checkDB(tool_ == OSQUERY_TOOL_DAEMON)) {
    LOG(ERROR) << binary_ << " initialize failed: Could not open RocksDB";
    if (isWorker()) {
      ::exit(EXIT_CATASTROPHIC);
    } else {
      ::exit(EXIT_FAILURE);
    }
  } else if (tool_ == OSQUERY_TOOL_DAEMON) {
    // A daemon must always have R/W access to the database.
    DBHandle::requireWrite();
  }

  // Bind to an extensions socket and wait for registry additions.
  osquery::startExtensionManager();

  // Then set the config plugin, which uses a single/active plugin.
  initActivePlugin("config", FLAGS_config_plugin);

  // Run the setup for all lazy registries (tables, SQL).
  Registry::setUp();

  if (FLAGS_config_check) {
    // The initiator requested an initialization and config check.
    auto s = Config::getInstance().load();
    if (!s.ok()) {
      std::cerr << "Error reading config: " << s.toString() << "\n";
    }
    // A configuration check exits the application.
    ::exit(s.getCode());
  }

  // Load the osquery config using the default/active config plugin.
  auto s = Config::getInstance().load();
  if (!s.ok()) {
    auto message = "Error reading config: " + s.toString();
    if (tool_ == OSQUERY_TOOL_DAEMON) {
      LOG(WARNING) << message;
    } else {
      LOG(INFO) << message;
    }
  }

  // Initialize the status and result plugin logger.
  initActivePlugin("logger", FLAGS_logger_plugin);
  initLogger(binary_);

  // Initialize the distributed plugin, if necessary
  if (!FLAGS_disable_distributed) {
    if (Registry::exists("distributed", FLAGS_distributed_plugin)) {
      initActivePlugin("distributed", FLAGS_distributed_plugin);
    }
  }

  // Start event threads.
  osquery::attachEvents();
  EventFactory::delay();
}

void Initializer::shutdown() {
  // End any event type run loops.
  EventFactory::end();

  // Hopefully release memory used by global string constructors in gflags.
  GFLAGS_NAMESPACE::ShutDownCommandLineFlags();
}
}
