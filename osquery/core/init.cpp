/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <chrono>
#include <iostream>
#include <random>
#include <thread>

#include <stdio.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <boost/filesystem.hpp>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/events.h>
#include <osquery/extensions.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry.h>

#include "osquery/core/watcher.h"
#include "osquery/dispatcher/dispatcher.h"

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
#define IOPRIO_BE_NR (8)

enum {
  IOPRIO_WHO_PROCESS = 1,
  IOPRIO_WHO_PGRP,
  IOPRIO_WHO_USER,
};
#endif

#ifdef __linux__
#define OSQUERY_HOME "/etc/osquery"
#else
#define OSQUERY_HOME "/var/osquery"
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
  "These options create files in " OSQUERY_HOME                               \
  " but it looks like that path "                                             \
  "has not\n"                                                                 \
  "been created. Please consider explicitly defining those "                  \
  "options as a different \n"                                                 \
  "path. Additionally, review the \"using osqueryd\" wiki page:\n"            \
  " - https://osquery.readthedocs.org/en/latest/introduction/using-osqueryd/" \
  "\n\n";

/// Seconds to alarm and quit for non-responsive event loops.
#define SIGNAL_ALARM_TIMEOUT 4

namespace {
extern "C" {
static inline bool hasWorkerVariable() {
  return (getenv("OSQUERY_WORKER") != nullptr);
}

volatile std::sig_atomic_t kHandledSignal{0};

static inline bool isWatcher() { return (osquery::Watcher::getWorker() > 0); }

void signalHandler(int num) {

  // Inform exit status of main threads blocked by service joins.
  if (kHandledSignal == 0) {
    kHandledSignal = num;
    // If no part of osquery requested an interruption then the exit 'wanted'
    // code becomes the signal number.
    if (num != SIGUSR1 && osquery::kExitCode == 0) {
      // The only exception is SIGUSR1 which is used to signal the main thread
      // to interrupt dispatched services.
      osquery::kExitCode = 128 + num;
    }

    // Handle signals based on a tri-state (worker, watcher, neither).
    if (num == SIGHUP) {
      if (!isWatcher() || hasWorkerVariable()) {
        // Reload configuration.
      }
    } else if (num == SIGTERM || num == SIGINT || num == SIGABRT ||
               num == SIGUSR1) {
      // Time to stop, set an upper bound time constraint on how long threads
      // have to terminate (join). Publishers may be in 20ms or similar sleeps.
      alarm(SIGNAL_ALARM_TIMEOUT);

      // Restore the default signal handler.
      std::signal(num, SIG_DFL);

      // The watcher waits for the worker to die.
      if (isWatcher()) {
        // Bind the fate of the worker to this watcher.
        osquery::Watcher::bindFates();
      } else {
        // Otherwise the worker or non-watched process joins.
        // Stop thrift services/clients/and their thread pools.
        osquery::Dispatcher::stopServices();
      }
    }
  }

  if (num == SIGALRM) {
    // Restore the default signal handler for SIGALRM.
    std::signal(SIGALRM, SIG_DFL);

    // Took too long to stop.
    VLOG(1) << "Cannot stop event publisher threads or services";
    raise((kHandledSignal != 0) ? kHandledSignal : SIGALRM);
  }

  if (isWatcher()) {
    // The signal should be proliferated through the process group.
    // Otherwise the watcher could 'forward' the signal to workers and
    // managed extension processes.
  }
}
}
}

namespace osquery {

using chrono_clock = std::chrono::high_resolution_clock;

#ifndef __APPLE__
CLI_FLAG(bool, daemonize, false, "Run as daemon (osqueryd only)");
#endif

DECLARE_string(distributed_plugin);
DECLARE_bool(disable_distributed);
DECLARE_string(config_plugin);
DECLARE_bool(config_check);
DECLARE_bool(config_dump);
DECLARE_bool(database_dump);
DECLARE_string(database_path);

ToolType kToolType = OSQUERY_TOOL_UNKNOWN;

volatile std::sig_atomic_t kExitCode{0};

/// The saved thread ID for shutdown to short-circuit raising a signal.
static std::thread::id kMainThreadId;

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
      binary_((tool == OSQUERY_TOOL_DAEMON) ? "osqueryd" : "osqueryi") {
  std::srand(chrono_clock::now().time_since_epoch().count());
  // The 'main' thread is that which executes the initializer.
  kMainThreadId = std::this_thread::get_id();

  // Handled boost filesystem locale problems fixes in 1.56.
  // See issue #1559 for the discussion and upstream boost patch.
  try {
    boost::filesystem::path::codecvt();
  } catch (const std::runtime_error& e) {
    setenv("LC_ALL", "C", 1);
  }

  // osquery implements a custom help/usage output.
  for (int i = 1; i < *argc_; i++) {
    auto help = std::string((*argv_)[i]);
    if ((help == "--help" || help == "-help" || help == "--h" ||
         help == "-h") &&
        tool != OSQUERY_TOOL_TEST) {
      printUsage(binary_, tool_);
      shutdown();
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
    // The shell never will not fork a worker.
    FLAGS_disable_watchdog = true;
    // Get the caller's home dir for temporary storage/state management.
    auto homedir = osqueryHomeDirectory();
    boost::system::error_code ec;
    if (osquery::pathExists(homedir).ok() ||
        boost::filesystem::create_directory(homedir, ec)) {
      // Only apply user/shell-specific paths if not overridden by CLI flag.
      if (Flag::isDefault("database_path")) {
        osquery::FLAGS_database_path = homedir + "/shell.db";
      }
      if (Flag::isDefault("extensions_socket")) {
        osquery::FLAGS_extensions_socket = homedir + "/shell.em";
      }
    } else {
      LOG(INFO) << "Cannot access or create osquery home directory";
      FLAGS_disable_extensions = true;
      FLAGS_database_path = "/dev/null";
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
  std::signal(SIGUSR1, signalHandler);

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

void Initializer::initDaemon() const {
  if (FLAGS_config_check) {
    // No need to daemonize, emit log lines, or create process mutexes.
    return;
  }

#ifndef __APPLE__
  // OS X uses launchd to daemonize.
  if (osquery::FLAGS_daemonize) {
    if (daemon(0, 0) == -1) {
      shutdown(EXIT_FAILURE);
    }
  }
#endif

  // Print the version to SYSLOG.
  syslog(
      LOG_NOTICE, "%s started [version=%s]", binary_.c_str(), kVersion.c_str());

  // Check if /var/osquery exists
  if ((Flag::isDefault("pidfile") || Flag::isDefault("database_path")) &&
      !isDirectory(OSQUERY_HOME)) {
    std::cerr << CONFIG_ERROR;
  }

  // Create a process mutex around the daemon.
  auto pid_status = createPidFile();
  if (!pid_status.ok()) {
    LOG(ERROR) << binary_ << " initialize failed: " << pid_status.toString();
    shutdown(EXIT_FAILURE);
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

void Initializer::initWatcher() const {
  // The watcher takes a list of paths to autoload extensions from.
  // The loadExtensions call will populate the watcher's list of extensions.
  osquery::loadExtensions();

  // Add a watcher service thread to start/watch an optional worker and list
  // of optional extensions from the autoload paths.
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
    auto retcode = 0;
    if (kHandledSignal > 0) {
      retcode = 128 + kHandledSignal;
    } else if (Watcher::getWorkerStatus() >= 0) {
      retcode = Watcher::getWorkerStatus();
    } else {
      retcode = EXIT_FAILURE;
    }
    requestShutdown(retcode);
  }
}

void Initializer::initWorker(const std::string& name) const {
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

  // Start a 'watcher watcher' thread to exit the process if the watcher exits.
  // In this case the parent process is called the 'watcher' process.
  Dispatcher::addService(std::make_shared<WatcherWatcherRunner>(getppid()));
}

void Initializer::initWorkerWatcher(const std::string& name) const {
  if (isWorker()) {
    initWorker(name);
  } else {
    // The watcher will forever monitor and spawn additional workers.
    initWatcher();
  }
}

bool Initializer::isWorker() { return hasWorkerVariable(); }

void Initializer::initActivePlugin(const std::string& type,
                                   const std::string& name) const {
  // Use a delay, meaning the amount of milliseconds waited for extensions.
  size_t delay = 0;
  // The timeout is the maximum microseconds in seconds to wait for extensions.
  size_t timeout = atoi(FLAGS_extensions_timeout.c_str()) * 1000000;
  if (timeout < kExtensionInitializeLatencyUS * 10) {
    timeout = kExtensionInitializeLatencyUS * 10;
  }

  // Attempt to set the request plugin as active.
  Status status;
  do {
    status = Registry::setActive(type, name);
    if (status.ok()) {
      // The plugin was found, and is not active.
      return;
    }

    if (!Watcher::hasManagedExtensions()) {
      // The plugin was found locally, and is not active, problem.
      break;
    }
    // The plugin is not local and is not active, wait and retry.
    delay += kExtensionInitializeLatencyUS;
    ::usleep(kExtensionInitializeLatencyUS);
  } while (delay < timeout);

  LOG(ERROR) << "Cannot activate " << name << " " << type
             << " plugin: " << status.getMessage();
  requestShutdown(EXIT_CATASTROPHIC);
}

void Initializer::start() const {
  // Load registry/extension modules before extensions.
  osquery::loadModules();

  // Pre-extension manager initialization options checking.
  // If the shell or daemon does not need extensions and it will exit quickly,
  // prefer to disable the extension manager.
  if ((FLAGS_config_check || FLAGS_config_dump) &&
      !Watcher::hasManagedExtensions()) {
    FLAGS_disable_extensions = true;
  }

  // A watcher should not need access to the backing store.
  // If there are spurious access then warning logs will be emitted since the
  // set-allow-open will never be called.
  if (!isWatcher()) {
    DatabasePlugin::setAllowOpen(true);
    // A daemon must always have R/W access to the database.
    DatabasePlugin::setRequireWrite(tool_ == OSQUERY_TOOL_DAEMON);
    if (!DatabasePlugin::initPlugin()) {
      LOG(ERROR) << RLOG(1629) << binary_
                 << " initialize failed: Could not initialize database";
      auto retcode = (isWorker()) ? EXIT_CATASTROPHIC : EXIT_FAILURE;
      requestShutdown(retcode);
    }
  }

  // Bind to an extensions socket and wait for registry additions.
  // After starting the extension manager, osquery MUST shutdown using the
  // internal 'shutdown' method.
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
    // Make sure to request a shutdown as plugins may have created services.
    requestShutdown(s.getCode());
  }

  if (FLAGS_database_dump) {
    dumpDatabase();
    requestShutdown();
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
  if (!FLAGS_disable_logging) {
    initActivePlugin("logger", FLAGS_logger_plugin);
  }
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

void Initializer::waitForShutdown() {
  // Attempt to be the only place in code where a join is attempted.
  Dispatcher::joinServices();
  // End any event type run loops.
  EventFactory::end(true);

  // Hopefully release memory used by global string constructors in gflags.
  GFLAGS_NAMESPACE::ShutDownCommandLineFlags();
  DatabasePlugin::shutdown();
  ::exit((kExitCode != 0) ? kExitCode : EXIT_SUCCESS);
}

void Initializer::requestShutdown(int retcode) {
  // Stop thrift services/clients/and their thread pools.
  kExitCode = retcode;
  if (std::this_thread::get_id() != kMainThreadId) {
    raise(SIGUSR1);
  } else {
    // The main thread is requesting a shutdown, meaning in almost every case
    // it is NOT waiting for a shutdown.
    // Exceptions include: tight request / wait in an exception handler or
    // custom signal handling.
    Dispatcher::stopServices();
    waitForShutdown();
  }
}

void Initializer::shutdown(int retcode) { ::exit(retcode); }
}
