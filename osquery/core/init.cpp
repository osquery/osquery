/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <chrono>
#include <future>
#include <iostream>
#include <random>
#include <thread>

#include <signal.h>
#include <stdio.h>
#include <time.h>

#ifdef WIN32
#include <WbemIdl.h>
#else
#include <unistd.h>
#endif

#ifndef WIN32
#include <sys/resource.h>
#endif

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/optional.hpp>

#include <osquery/config/config.h>
#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/core/shutdown.h>
#include <osquery/core/watcher.h>
#include <osquery/dispatcher/dispatcher.h>
#include <osquery/events/eventfactory.h>
#include <osquery/events/events.h>
#include <osquery/extensions/extensions.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/data_logger.h>
#include <osquery/numeric_monitoring/numeric_monitoring.h>
#include <osquery/process/process.h>
#include <osquery/registry/registry.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/config/default_paths.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/info/version.h>
#include <osquery/utils/pidfile/pidfile.h>
#include <osquery/utils/system/system.h>
#include <osquery/utils/system/time.h>

#ifdef WIN32
#include <osquery/core/windows/global_users_groups_cache.h>
#include <osquery/system/usersgroups/windows/groups_service.h>
#include <osquery/system/usersgroups/windows/users_service.h>
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

using chrono_clock = std::chrono::high_resolution_clock;

namespace fs = boost::filesystem;

DECLARE_string(flagfile);

namespace osquery {

DECLARE_string(config_plugin);
DECLARE_string(logger_plugin);
DECLARE_string(numeric_monitoring_plugins);
DECLARE_string(distributed_plugin);
DECLARE_bool(config_check);
DECLARE_bool(config_dump);
DECLARE_bool(database_dump);
DECLARE_string(database_path);
DECLARE_bool(disable_distributed);
DECLARE_bool(disable_database);
DECLARE_bool(disable_events);
DECLARE_bool(disable_logging);
DECLARE_bool(enable_numeric_monitoring);

CLI_FLAG(bool, S, false, "Run as a shell process");
CLI_FLAG(bool, D, false, "Run as a daemon process");
CLI_FLAG(bool, daemonize, false, "Attempt to daemonize (POSIX only)");
CLI_FLAG(uint64,
         alarm_timeout,
         15,
         "Seconds to allow for shutdown. Minimum is 10");
#ifdef OSQUERY_LINUX

/* The default value here is just a placeholder,
   it will be recalculated at runtime */
FLAG(uint64,
     malloc_trim_threshold,
     200,
     "Memory threshold in MB used to decide when a malloc_trim will be called "
     "to reduce the retained memory (Linux only)")
#endif

/// Should the daemon force unload previously-running osqueryd daemons.
CLI_FLAG(bool,
         force,
         false,
         "Force osqueryd to kill previously-running daemons");

FLAG(bool, ephemeral, false, "Skip pidfile and database state checks");

/// The path to the pidfile for osqueryd
CLI_FLAG(string,
         pidfile,
         OSQUERY_PIDFILE "osqueryd.pidfile",
         "Path to the daemon pidfile mutex");

/// The saved thread ID for shutdown to short-circuit raising a signal.
static std::thread::id kMainThreadId;

#ifdef OSQUERY_WINDOWS
/// Legacy thread ID to ensure that the windows service waits before exiting
DWORD kLegacyThreadId;
#endif

/// When no flagfile is provided via CLI, attempt to read flag 'defaults'.
const std::string kBackupDefaultFlagfile{OSQUERY_HOME "osquery.flags.default"};

struct Initializer::PrivateData final {
  /// Either a pidfile or std::nullopt for ephemeral instances
  boost::optional<Pidfile> opt_pidfile;
};

bool Initializer::isWorker_{false};
std::atomic<bool> Initializer::resource_limit_hit_{false};

namespace {

static inline bool hasWorkerVariable() {
  return getEnvVar("OSQUERY_WORKER").is_initialized();
}

void initWorkDirectories() {
  if (!FLAGS_disable_database) {
    auto const recursive = true;
    auto const ignore_existence = true;
    auto const status =
        createDirectory(fs::path(FLAGS_database_path).parent_path(),
                        recursive,
                        ignore_existence);
    if (!status.ok()) {
      LOG(ERROR) << "Could not initialize db directory: " << status.what();
    }
  }
}

void signalHandler(int num) {
  int rc = 0;

  if (num == SIGUSR1) {
    Initializer::resourceLimitHit();
  }

  // Expect SIGTERM and SIGINT to gracefully shutdown.
  // Other signals are unexpected.
  else if (num != SIGTERM && num != SIGINT) {
    rc = 128 + num;
  }

  Initializer::requestShutdown(rc);
}

bool validateAlarmTimeout(const char* flagname, std::uint64_t value) {
  if (value < 10) {
    osquery::systemLog("Alarm timeout cannot be lower than 10 seconds");
    std::cerr << "Alarm timeout cannot be lower than 10 seconds" << std::endl;
    return false;
  }

  return true;
}
} // namespace

DEFINE_validator(alarm_timeout, &validateAlarmTimeout);

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
  fflush(stdout);
}

Initializer::Initializer(int& argc,
                         char**& argv,
                         ToolType tool,
                         bool const init_glog)
    : d(new PrivateData), argc_(&argc), argv_(&argv) {
  // Initialize random number generated based on time.
  std::srand(static_cast<unsigned int>(
      chrono_clock::now().time_since_epoch().count()));
  // The config holds the initialization time for easy access.
  setStartTime(getUnixTime());

  isWorker_ = hasWorkerVariable();

  // osquery can function as the daemon or shell depending on argv[0].
  if (tool == ToolType::SHELL_DAEMON) {
    if (fs::path(argv[0]).filename().string().find("osqueryd") !=
        std::string::npos) {
      setToolType(ToolType::DAEMON);
      binary_ = "osqueryd";
    } else {
      setToolType(ToolType::SHELL);
      binary_ = "osqueryi";
    }
  } else {
    // Set the tool type to allow runtime decisions based on daemon, shell, etc.
    setToolType(tool);
  }

  // The 'main' thread is that which executes the initializer.
  kMainThreadId = std::this_thread::get_id();

#ifdef OSQUERY_WINDOWS
  // Maintain a legacy thread id for Windows service stops.
  kLegacyThreadId = static_cast<DWORD>(platformGetTid());
#endif

#ifndef WIN32
  // Set the max number of open files.
  struct rlimit nofiles;
  if (getrlimit(RLIMIT_NOFILE, &nofiles) == 0) {
    if (nofiles.rlim_cur < 1024 || nofiles.rlim_max < 1024) {
      nofiles.rlim_cur = (nofiles.rlim_cur < 1024) ? 1024 : nofiles.rlim_cur;
      nofiles.rlim_max = (nofiles.rlim_max < 1024) ? 1024 : nofiles.rlim_max;
      setrlimit(RLIMIT_NOFILE, &nofiles);
    }
  }
#endif

  Flag::create("logtostderr",
               {"Log messages to stderr in addition to the logger plugin(s)",
                false,
                false,
                true,
                false});
  Flag::create("stderrthreshold",
               {"Stderr log level threshold", false, false, true, false});

  // osquery implements a custom help/usage output.
  bool default_flags = true;
  for (int i = 1; i < *argc_; i++) {
    auto help = std::string((*argv_)[i]);
    if (help == "-S" || help == "--S") {
      setToolType(ToolType::SHELL);
      binary_ = "osqueryi";
    } else if (help == "-D" || help == "--D") {
      setToolType(ToolType::DAEMON);
      binary_ = "osqueryd";
    } else if ((help == "--help" || help == "-help" || help == "--h" ||
                help == "-h") &&
               tool != ToolType::TEST) {
      printUsage(binary_, getToolType());
      shutdownNow();
      return;
    }
    if (help.find("--flagfile") == 0) {
      default_flags = false;
    }
  }

  if (isShell()) {
    // Configure default flag values that are different for the shell.
    // Since these are set before flags are parsed, it is possible for the CLI
    // to overwrite them.
    FLAGS_disable_events = true;
  }

  if (default_flags && isReadable(kBackupDefaultFlagfile)) {
    // No flagfile was set (daemons and services always set a flagfile).
    FLAGS_flagfile = kBackupDefaultFlagfile;
  } else {
    // No flagfile was set, but no default flags exist.
    default_flags = false;
  }

  // Set version string from CMake build
  GFLAGS_NAMESPACE::SetVersionString(kVersion.c_str());

  // Let gflags parse the non-help options/flags.
  GFLAGS_NAMESPACE::ParseCommandLineFlags(argc_, argv_, isShell());

  if (isShell()) {
    // Do not set these values before calling ParseCommandLineFlags.
    // These values are force-set and ignore the configuration and CLI.
    FLAGS_disable_logging = true;
    FLAGS_disable_watchdog = true;
  }

  // Initialize registries and plugins
  registryAndPluginInit();

  if (isShell() || FLAGS_ephemeral) {
    if (Flag::isDefault("database_path") &&
        Flag::isDefault("disable_database")) {
      // The shell should not use a database by default, but should use the DB
      // specified by database_path if it is set
      FLAGS_disable_database = true;
    }
  }

  if (isShell()) {
    // Initialize the shell after setting modified defaults and parsing flags.
    initShell();
  }
  if (isDaemon()) {
    initWorkDirectories();
  }

  std::signal(SIGTERM, signalHandler);
  std::signal(SIGINT, signalHandler);
  std::signal(SIGUSR1, signalHandler);

  // If the caller is checking configuration, disable the watchdog/worker.
  if (FLAGS_config_check || FLAGS_database_dump || FLAGS_config_dump) {
    FLAGS_disable_watchdog = true;
  }

  if (isWatcher()) {
    FLAGS_disable_database = true;
    FLAGS_disable_logging = true;
  }

  // Initialize the status and results logger.
  initStatusLogger(binary_, init_glog);
  if (getToolType() != ToolType::EXTENSION) {
    if (isWorker()) {
      VLOG(1) << "osquery worker initialized [watcher="
              << PlatformProcess::getLauncherProcess()->pid() << "]";
    } else {
      VLOG(1) << "osquery initialized [version=" << kVersion << "]";
    }
  } else {
    VLOG(1) << "osquery extension initialized [sdk=" << kVersion << "]";
  }

  if (default_flags) {
    VLOG(1) << "Using default flagfile: " << kBackupDefaultFlagfile;
  }

  // Initialize the COM libs
  platformSetup();
}

Initializer::~Initializer() {}

bool terminateActiveOsqueryInstance() {
  auto pid_res = Pidfile::read(FLAGS_pidfile);
  if (pid_res.isError()) {
    auto error = pid_res.getErrorCode();

    if (error != Pidfile::Error::NotRunning) {
      LOG(ERROR) << "Failed to read the pidfile: " << error;
    }

    return false;
  }

  auto pid = static_cast<int>(pid_res.take());
  if (pid == PlatformProcess::getCurrentPid()) {
    return true;
  }

  // The pid is running, check if it is an osqueryd process by name.
  std::stringstream query_text;

  query_text << "SELECT name FROM processes WHERE pid = " << pid
             << " AND name LIKE 'osqueryd%';";

  SQL q(query_text.str());
  if (!q.ok()) {
    LOG(ERROR) << "Error querying processes: " << q.getMessageString();
    return false;
  }

  if (q.rows().size() > 0) {
    // Do not use SIGQUIT as it will cause a crash on OS X.
    PlatformProcess target(pid);
    auto kill_succeeded = target.kill();

    LOG(ERROR) << "Killing osqueryd process: " << pid << " ("
               << (kill_succeeded ? "succeeded" : "failed") << ")";

    return true;

  } else {
    LOG(ERROR) << "Refusing to kill non-osqueryd process " << pid;
    return false;
  }
}

void Initializer::initDaemon() const {
  if (isWorker() || !isDaemon()) {
    // The worker process (child) will not daemonize.
    return;
  }

  if (FLAGS_config_check || FLAGS_database_dump || FLAGS_config_dump) {
    // No need to daemonize, emit log lines, or create process mutexes.
    return;
  }

#if !defined(__APPLE__) && !defined(WIN32)
  // OS X uses launchd to daemonize.
  if (osquery::FLAGS_daemonize) {
    if (daemon(0, 0) == -1) {
      shutdownNow(EXIT_FAILURE);
    }
  }
#endif

  // Print the version to the OS system log.
  systemLog(binary_ + " started [version=" + kVersion + "]");

  if (!FLAGS_ephemeral) {
    auto pidfile_path = fs::path(FLAGS_pidfile).make_preferred().string();

    auto pidfile_res = Pidfile::create(pidfile_path);
    if (pidfile_res.isError() &&
        pidfile_res.getErrorCode() == Pidfile::Error::Busy && FLAGS_force) {
      if (terminateActiveOsqueryInstance()) {
        for (int retry = 0; retry < 5; ++retry) {
          sleepFor(2000);

          pidfile_res = Pidfile::create(pidfile_path);
          if (pidfile_res.isValue()) {
            break;
          }

          VLOG(1) << binary_ << " Pidfile initialization failed: "
                  << pidfile_res.getErrorCode() << " (retry: " << retry + 1
                  << "/5)";
        }
      }
    }

    if (pidfile_res.isError()) {
      LOG(ERROR) << binary_
                 << " Pidfile check failed: " << pidfile_res.getErrorCode();

      shutdownNow(EXIT_FAILURE);
    }

    d->opt_pidfile = pidfile_res.take();
  }

  // Nice ourselves if using a watchdog and the level is not too permissive.
  if (!FLAGS_disable_watchdog && FLAGS_watchdog_level >= 0) {
    // Set CPU scheduling I/O limits.
    // On windows these values are inherited so no further calls are needed.
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

  if (Flag::isDefault("hash_delay")) {
    // The hash_delay is designed for daemons only.
    Flag::updateValue("hash_delay", "0");
  }
}

void Initializer::initWatcher() const {
  auto watcher = std::make_shared<Watcher>();

  // The watcher should not log into or use a persistent database.
  // The watcher already disabled database usage.
  if (isWatcher()) {
    setDatabaseAllowOpen();
    initDatabasePlugin();
  }

  // The watcher takes a list of paths to autoload extensions from.
  // The loadExtensions call will populate the watcher's list of extensions.
  watcher->loadExtensions();

  // Add a watcher service thread to start/watch an optional worker and list
  // of optional extensions from the autoload paths.
  if (Watcher::hasManagedExtensions() || !FLAGS_disable_watchdog) {
    Dispatcher::addService(
        std::make_shared<WatcherRunner>(*argc_, *argv_, isWatcher(), watcher));
  }

  if (isWatcher()) {
    // If this process is a watchdog it will do nothing but monitor the
    // extensions and worker process. This is its main thread and it should
    // wait until shutdown.
    waitForShutdown();

    // Do not start new workers.
    watcher->bindFates();
    if (watcher->getWorkerStatus() >= 0) {
      setShutdownExitCode(watcher->getWorkerStatus());
    }
  }
}

void Initializer::initWorker(const std::string& name) const {
  // Clear worker's arguments.
  auto original_name = std::string((*argv_)[0]);
  for (int i = 1; i < *argc_; i++) {
    if ((*argv_)[i] != nullptr) {
      memset((*argv_)[i], '\0', strlen((*argv_)[i]));
    }
  }

  // Start a 'watcher watcher' thread to exit the process if the watcher exits.
  // In this case the parent process is called the 'watcher' process.
  Dispatcher::addService(std::make_shared<WatcherWatcherRunner>(
      PlatformProcess::getLauncherProcess()));
}

void Initializer::initWorkerWatcher(const std::string& name) const {
  if (isWorker() || !isWatcher()) {
#ifdef OSQUERY_WINDOWS
    std::promise<void> users_cache_promise;
    std::promise<void> groups_cache_promise;
    GlobalUsersGroupsCache::global_users_cache_future_ =
        users_cache_promise.get_future();
    GlobalUsersGroupsCache::global_groups_cache_future_ =
        groups_cache_promise.get_future();

    Dispatcher::addService(std::make_shared<UsersService>(
        std::move(users_cache_promise),
        GlobalUsersGroupsCache::global_users_cache_));
    Dispatcher::addService(std::make_shared<GroupsService>(
        std::move(groups_cache_promise),
        GlobalUsersGroupsCache::global_groups_cache_));
#endif
  }

  if (isWorker()) {
    initWorker(name);
  } else {
    // The watcher will forever monitor and spawn additional workers.
    // This initialize will handle work for processes without watchdogs too.
    initWatcher();
  }
}

bool Initializer::isWorker() {
  return isWorker_;
}

bool Initializer::isWatcher() {
  return !FLAGS_disable_watchdog && !isWorker();
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
    std::string message = "Cannot activate " + name + " " + type +
                          " plugin: " + status.getMessage();
    requestShutdown(EXIT_CATASTROPHIC, message);
  }
}

void Initializer::start() const {
  // Pre-extension manager initialization options checking.
  // If the shell or daemon does not need extensions and it will exit quickly,
  // prefer to disable the extension manager.
  if ((FLAGS_config_check || FLAGS_config_dump || FLAGS_database_dump) &&
      !Watcher::hasManagedExtensions()) {
    FLAGS_disable_extensions = true;
  }

  if (!isWatcher()) {
    setDatabaseAllowOpen();
    auto status = initDatabasePlugin();
    if (!status.ok()) {
      auto retcode = (isWorker()) ? EXIT_CATASTROPHIC : EXIT_FAILURE;
      requestShutdown(retcode, status.getMessage());
      return;
    }

    // Ensure the database results version is up to date before proceeding
    if (!upgradeDatabase()) {
      auto retcode = (isWorker()) ? EXIT_CATASTROPHIC : EXIT_FAILURE;
      requestShutdown(retcode, "Failed to upgrade database");
      return;
    }
  }

  // Bind to an extensions socket and wait for registry additions.
  // After starting the extension manager, osquery MUST shutdown using the
  // internal 'shutdown' method.
  auto s = osquery::startExtensionManager();
  if (!s.ok()) {
    auto error_message =
        "An error occurred during extension manager startup: " + s.getMessage();
    auto severity =
        (FLAGS_disable_extensions) ? google::GLOG_INFO : google::GLOG_ERROR;
    if (severity == google::GLOG_INFO) {
      VLOG(1) << error_message;
    } else {
      google::LogMessage(__FILE__, __LINE__, severity).stream()
          << error_message;
    }
  }

  if (shutdownRequested()) {
    return;
  }

  // Then set the config plugin, which uses a single/active plugin.
  initActivePlugin("config", FLAGS_config_plugin);

  if (shutdownRequested()) {
    return;
  }

  // Run the setup for all lazy registries (tables, SQL).
  Registry::setUp();

  if (FLAGS_config_check) {
    // The initiator requested an initialization and config check.
    s = Config::get().load();
    if (!s.ok()) {
      std::cerr << "Error reading config: " << s.toString() << "\n";
    }
    // A configuration check exits the application.
    // Make sure to request a shutdown as plugins may have created services.
    requestShutdown(s.getCode());
    return;
  }

  if (FLAGS_database_dump) {
    dumpDatabase();
    requestShutdown();
    return;
  }

  if (shutdownRequested()) {
    return;
  }

  // Load the osquery config using the default/active config plugin.
  s = Config::get().load();
  if (!s.ok()) {
    auto message = "Error reading config: " + s.toString();
    if (isDaemon()) {
      LOG(WARNING) << message;
    } else {
      VLOG(1) << message;
    }
  }

  // Initialize the status and result plugin logger.
  if (!FLAGS_disable_logging) {
    if (shutdownRequested()) {
      return;
    }

    initActivePlugin("logger", FLAGS_logger_plugin);

    if (shutdownRequested()) {
      return;
    }

    initLogger(binary_);
  }

  // Initialize the distributed plugin, if necessary
  if (!FLAGS_disable_distributed) {
    if (shutdownRequested()) {
      return;
    }

    initActivePlugin("distributed", FLAGS_distributed_plugin);
  }

  if (FLAGS_enable_numeric_monitoring) {
    if (shutdownRequested()) {
      return;
    }

    initActivePlugin(monitoring::registryName(),
                     FLAGS_numeric_monitoring_plugins);
  }

  if (shutdownRequested()) {
    return;
  }

  // Start event threads.
  attachEvents();

  if (shutdownRequested()) {
    return;
  }

  EventFactory::delay();
}

void Initializer::resourceLimitHit() {
  resource_limit_hit_ = true;
}

bool Initializer::isResourceLimitHit() {
  return resource_limit_hit_.load();
}

/**
 * This is a small interruptible thread implementation.
 *
 * The goal is to wait until interrupted or an alarm timeout. If the timeout
 * occurs then osquery is stuck shutting down and we force-terminate.
 */
class AlarmRunnable : public InterruptibleRunnable {
 public:
  /// Thread entry point.
  void run() {
    size_t waited = 0;
    while (true) {
      if (interrupted()) {
        return;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
      waited += 200;
      if (waited > FLAGS_alarm_timeout * 1000) {
        Initializer::shutdownNow(EXIT_CATASTROPHIC);
      }
    }
  }

 private:
  /// No custom stop logic.
  void stop() {}
};

void Initializer::waitForShutdown() const {
  osquery::waitForShutdown();
}

int Initializer::shutdown(int retcode) const {
  // Should only be called from main thread.
  auto current_thread_id = std::this_thread::get_id();
  if (current_thread_id != kMainThreadId) {
    // Unintended usage.
    throw std::runtime_error("Requested shutdown from service thread");
  }

  // Create an alarm thread, which will force-stop the process.
  AlarmRunnable alarm_runnable;
  auto alarm_thread = std::make_unique<std::thread>(
      std::bind(&AlarmRunnable::run, &alarm_runnable));

  // Request that all services stop.
  Dispatcher::stopServices();
  // Attempt to be the only place in code where a join is attempted.
  Dispatcher::joinServices();
  // End any event type run loops.
  EventFactory::end(true);

  // Hopefully release memory used by global string constructors in gflags.
  GFLAGS_NAMESPACE::ShutDownCommandLineFlags();
  shutdownDatabase();

  // Cancel the alarm.
  alarm_runnable.interrupt();
  alarm_thread->join();

  platformTeardown();

  // Allow the retcode to override a stored request for shutdown.
  return (retcode == 0) ? getShutdownExitCode() : retcode;
}

void Initializer::requestShutdown(int retcode) {
  osquery::requestShutdown(retcode);
}

void Initializer::requestShutdown(int retcode, const std::string& message) {
  osquery::requestShutdown(retcode, message);
}

void Initializer::shutdownNow(int retcode) {
  platformTeardown();
  _Exit(retcode);
}
} // namespace osquery
