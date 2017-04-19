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
#include <time.h>

#ifdef WIN32
#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
#include <WbemIdl.h>
#include <Windows.h>
#include <signal.h>
#else
#include <unistd.h>
#endif

#include <boost/filesystem.hpp>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/dispatcher.h>
#include <osquery/events.h>
#include <osquery/extensions.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/system.h>

#include "osquery/core/process.h"
#include "osquery/core/watcher.h"

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

#define DESCRIPTION                                                            \
  "osquery %s, your OS as a high-performance relational database\n"
#define EPILOG "\nosquery project page <https://osquery.io>.\n"
#define OPTIONS                                                                \
  "\nosquery configuration options (set by config or CLI flags):\n\n"
#define OPTIONS_SHELL "\nosquery shell-only CLI flags:\n\n"
#define OPTIONS_CLI "osquery%s command line flags:\n\n"
#define USAGE "Usage: %s [OPTION]... %s\n\n"
#define CONFIG_ERROR                                                           \
  "You are using default configurations for osqueryd for one or more of the "  \
  "following\n"                                                                \
  "flags: pidfile, db_path.\n\n"                                               \
  "These options create files in " OSQUERY_HOME                                \
  " but it looks like that path "                                              \
  "has not\n"                                                                  \
  "been created. Please consider explicitly defining those "                   \
  "options as a different \n"                                                  \
  "path. Additionally, review the \"using osqueryd\" wiki page:\n"             \
  " - https://osquery.readthedocs.org/en/latest/introduction/using-osqueryd/"  \
  "\n\n";

/// For Windows, SIGILL and SIGTERM
#ifdef WIN32

/// We define SIGHUP similarly to POSIX because otherwise it would require a
/// complex ifndef
#define SIGHUP 1

/// For Windows, SIGILL and SIGTERM are not generated signals. To supplant the
/// SIGUSR1 use-case on POSIX, we use SIGILL.
#define SIGUSR1 SIGILL

#endif

namespace osquery {
CLI_FLAG(uint64, alarm_timeout, 4, "Seconds to wait for a graceful shutdown");
}

namespace {
extern "C" {
static inline bool hasWorkerVariable() {
  return ::osquery::getEnvVar("OSQUERY_WORKER").is_initialized();
}

volatile std::sig_atomic_t kHandledSignal{0};

static inline bool isWatcher() {
  return (osquery::Watcher::getWorker().isValid());
}

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
#ifndef WIN32
      // Time to stop, set an upper bound time constraint on how long threads
      // have to terminate (join). Publishers may be in 20ms or similar sleeps.
      alarm(osquery::FLAGS_alarm_timeout);
#endif

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

#ifndef WIN32
  if (num == SIGALRM) {
    // Restore the default signal handler for SIGALRM.
    std::signal(SIGALRM, SIG_DFL);

    // Took too long to stop.
    VLOG(1) << "Cannot stop event publisher threads or services";
    raise((kHandledSignal != 0) ? kHandledSignal : SIGALRM);
  }
#endif

  if (isWatcher()) {
    // The signal should be proliferated through the process group.
    // Otherwise the watcher could 'forward' the signal to workers and
    // managed extension processes.
  }
}
}
}

using chrono_clock = std::chrono::high_resolution_clock;

namespace fs = boost::filesystem;

DECLARE_string(flagfile);

namespace osquery {

DECLARE_string(config_plugin);
DECLARE_bool(config_check);
DECLARE_bool(config_dump);
DECLARE_bool(database_dump);
DECLARE_string(database_path);
DECLARE_string(distributed_plugin);
DECLARE_bool(disable_distributed);
DECLARE_bool(disable_database);
DECLARE_bool(disable_events);

#if !defined(__APPLE__) && !defined(WIN32)
CLI_FLAG(bool, daemonize, false, "Run as daemon (osqueryd only)");
#endif

FLAG(bool, ephemeral, false, "Skip pidfile and database state checks");

ToolType kToolType = ToolType::UNKNOWN;

volatile std::sig_atomic_t kExitCode{0};

/// The saved thread ID for shutdown to short-circuit raising a signal.
static std::thread::id kMainThreadId;

const std::string kDefaultFlagfile = OSQUERY_HOME "/osquery.flags.default";

const size_t Initializer::kDatabaseMaxRetryCount = 3;
const size_t Initializer::kDatabaseRetryDelay = 5000;

static inline void printUsage(const std::string& binary, ToolType tool) {
  // Parse help options before gflags. Only display osquery-related options.
  fprintf(stdout, DESCRIPTION, kVersion.c_str());
  if (tool == ToolType::SHELL) {
    // The shell allows a caller to run a single SQL statement and exit.
    fprintf(stdout, USAGE, binary.c_str(), "[SQL STATEMENT]");
  } else {
    fprintf(stdout, USAGE, binary.c_str(), "");
  }

  if (tool == ToolType::EXTENSION) {
    fprintf(stdout, OPTIONS_CLI, " extension");
    Flag::printFlags(false, true);
  } else {
    fprintf(stdout, OPTIONS_CLI, "");
    Flag::printFlags(false, false, true);
    fprintf(stdout, OPTIONS);
    Flag::printFlags();
  }

  if (tool == ToolType::SHELL) {
    // Print shell flags.
    fprintf(stdout, OPTIONS_SHELL);
    Flag::printFlags(true);
  }

  fprintf(stdout, EPILOG);
}

void Initializer::platformSetup() {
// Initialize the COM libraries utilized by Windows WMI calls.
#ifdef WIN32
  auto ret = ::CoInitializeEx(0, COINIT_MULTITHREADED);
  if (ret != S_OK) {
    ::CoUninitialize();
  }
#else
#endif
}

void Initializer::platformTeardown() {
// Before we shutdown, we must insure to free the COM libs in windows
#ifdef WIN32
  ::CoUninitialize();
#else
#endif
}

Initializer::Initializer(int& argc, char**& argv, ToolType tool)
    : argc_(&argc),
      argv_(&argv),
      tool_(tool),
      binary_((tool == ToolType::DAEMON) ? "osqueryd" : "osqueryi") {
  std::srand(static_cast<unsigned int>(
      chrono_clock::now().time_since_epoch().count()));

  // Initialize registries and plugins
  registryAndPluginInit();

  // The 'main' thread is that which executes the initializer.
  kMainThreadId = std::this_thread::get_id();
  // Set the tool type to allow runtime decisions based on daemon, shell, etc.
  kToolType = tool;

  // Handled boost filesystem locale problems fixes in 1.56.
  // See issue #1559 for the discussion and upstream boost patch.
  try {
    boost::filesystem::path::codecvt();
  } catch (const std::runtime_error& /* e */) {
#ifdef WIN32
    setlocale(LC_ALL, "C");
#else
    setenv("LC_ALL", "C", 1);
#endif
  }

  Flag::create("logtostderr",
               {"Log messages to stderr in addition to the logger plugin(s)",
                false,
                false,
                true,
                false});
  Flag::create("stderrthreshold",
               {"Stderr log level threshold", false, false, true, false});

  // osquery implements a custom help/usage output.
  for (int i = 1; i < *argc_; i++) {
    auto help = std::string((*argv_)[i]);
    if ((help == "--help" || help == "-help" || help == "--h" ||
         help == "-h") &&
        tool != ToolType::TEST) {
      printUsage(binary_, tool_);
      shutdown();
    }
  }

  if (tool == ToolType::SHELL) {
    // The shell is transient, rewrite config-loaded paths.
    FLAGS_disable_logging = true;
    // The shell never will not fork a worker.
    FLAGS_disable_watchdog = true;
    FLAGS_disable_events = true;
  }

  bool default_flags = false;
  if (FLAGS_flagfile.empty() && isReadable(kDefaultFlagfile)) {
    // No flagfile was set (daemons and services always set a flagfile).
    default_flags = true;
    FLAGS_flagfile = kDefaultFlagfile;
  }

  // Set version string from CMake build
  GFLAGS_NAMESPACE::SetVersionString(kVersion.c_str());

  // Let gflags parse the non-help options/flags.
  GFLAGS_NAMESPACE::ParseCommandLineFlags(
      argc_, argv_, (tool == ToolType::SHELL));

  if (tool == ToolType::SHELL) {
    if (Flag::isDefault("database_path") &&
        Flag::isDefault("disable_database")) {
      // The shell should not use a database by default, but should use the DB
      // specified by database_path if it is set
      FLAGS_disable_database = true;
    }
    // Initialize the shell after setting modified defaults and parsing flags.
    initShell();
  } else {
    // The daemon will only output ERROR logs to stderr.
    if (Flag::isDefault("stderrthreshold")) {
      Flag::updateValue("stderrthreshold", "2");
    }
  }

#ifndef WIN32
  // All tools handle the same set of signals.
  // If a daemon process is a watchdog the signal is passed to the worker,
  // unless the worker has not yet started.
  std::signal(SIGTERM, signalHandler);
  std::signal(SIGINT, signalHandler);
  std::signal(SIGHUP, signalHandler);
  std::signal(SIGALRM, signalHandler);
  std::signal(SIGCHLD, SIG_IGN);
#endif

  std::signal(SIGABRT, signalHandler);
  std::signal(SIGUSR1, signalHandler);

  // If the caller is checking configuration, disable the watchdog/worker.
  if (FLAGS_config_check) {
    FLAGS_disable_watchdog = true;
  }

  // Initialize the status and results logger.
  initStatusLogger(binary_);
  if (tool != ToolType::EXTENSION) {
    if (isWorker()) {
      VLOG(1) << "osquery worker initialized [watcher="
              << PlatformProcess::getLauncherProcess()->pid() << "]";
    } else {
      VLOG(1) << "osquery initialized [version=" << kVersion << "]";
    }
  } else {
    VLOG(1) << "osquery extension initialized [sdk=" << kSDKVersion << "]";
  }

  if (default_flags) {
    VLOG(1) << "Using default flagfile: " << kDefaultFlagfile;
  }

  // Initialize the COM libs
  platformSetup();
}

void Initializer::initDaemon() const {
  if (FLAGS_config_check) {
    // No need to daemonize, emit log lines, or create process mutexes.
    return;
  }

#if !defined(__APPLE__) && !defined(WIN32)
  // OS X uses launchd to daemonize.
  if (osquery::FLAGS_daemonize) {
    if (daemon(0, 0) == -1) {
      shutdown(EXIT_FAILURE);
    }
  }
#endif

  // Print the version to the OS system log.
  systemLog(binary_ + " started [version=" + kVersion + "]");

  if (!FLAGS_ephemeral) {
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
  }

  // Nice ourselves if using a watchdog and the level is not too permissive.
  if (!FLAGS_disable_watchdog && FLAGS_watchdog_level >= 0) {
    // Set CPU scheduling I/O limits.
    setToBackgroundPriority();

#ifdef __linux__
    // Using: ioprio_set(IOPRIO_WHO_PGRP, 0, IOPRIO_CLASS_IDLE);
    syscall(SYS_ioprio_set, IOPRIO_WHO_PGRP, 0, IOPRIO_CLASS_IDLE);
#elif defined(__APPLE__)
    setiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_PROCESS, IOPOL_THROTTLE);
#endif
  }
}

void Initializer::initShell() const {
  // Get the caller's home dir for temporary storage/state management.
  auto homedir = osqueryHomeDirectory();
  if (osquery::pathExists(homedir).ok()) {
    // Only apply user/shell-specific paths if not overridden by CLI flag.
    if (Flag::isDefault("database_path")) {
      osquery::FLAGS_database_path =
          (fs::path(homedir) / "shell.db").make_preferred().string();
    }
    initShellSocket(homedir);
  } else {
    fprintf(
        stderr, "Cannot access or create osquery home: %s", homedir.c_str());
    FLAGS_disable_extensions = true;
    FLAGS_disable_database = true;
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
}

void Initializer::waitForWatcher() const {
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
      memset((*argv_)[i], '\0', strlen((*argv_)[i]));
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
  Dispatcher::addService(std::make_shared<WatcherWatcherRunner>(
      PlatformProcess::getLauncherProcess()));
}

void Initializer::initWorkerWatcher(const std::string& name) const {
  if (isWorker()) {
    initWorker(name);
  } else {
    // The watcher will forever monitor and spawn additional workers.
    initWatcher();
    waitForWatcher();
  }
}

bool Initializer::isWorker() {
  return hasWorkerVariable();
}

void Initializer::initActivePlugin(const std::string& type,
                                   const std::string& name) const {
  auto status = applyExtensionDelay(([type, name](bool& stop) {
    auto rs = RegistryFactory::get().setActive(type, name);
    if (rs.ok()) {
      // The plugin was found, and is now active.
      return rs;
    }

    if (!Watcher::hasManagedExtensions()) {
      // The plugin must be local, and is not active, problem.
      stop = true;
    }
    return rs;
  }));

  if (!status.ok()) {
    LOG(ERROR) << "Cannot activate " << name << " " << type
               << " plugin: " << status.getMessage();
    requestShutdown(EXIT_CATASTROPHIC);
  }
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
    DatabasePlugin::setRequireWrite(tool_ == ToolType::DAEMON);

    for (size_t i = 1; i <= kDatabaseMaxRetryCount; i++) {
      auto ok = DatabasePlugin::initPlugin();
      if (ok) {
        break;
      }

      if (i == kDatabaseMaxRetryCount) {
        LOG(ERROR) << RLOG(1629) << binary_
                   << " initialize failed: Could not initialize database";
        auto retcode = (isWorker()) ? EXIT_CATASTROPHIC : EXIT_FAILURE;
        requestShutdown(retcode);
      }

      LOG(WARNING) << RLOG(1629) << binary_
                   << " initialize failed: Could not initialize database";
      LOG(INFO) << "Waiting " << (kDatabaseRetryDelay / 1000)
                << " seconds before attempting to re-initialize database...";
      sleepFor(kDatabaseRetryDelay);
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
    if (tool_ == ToolType::DAEMON) {
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
    initActivePlugin("distributed", FLAGS_distributed_plugin);
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

void Initializer::requestShutdown(int retcode, const std::string& system_log) {
  systemLog(system_log);
  requestShutdown(retcode);
}

void Initializer::shutdown(int retcode) {
  platformTeardown();
  ::exit(retcode);
}
}
