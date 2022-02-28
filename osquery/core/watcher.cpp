/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <chrono>
#include <cstring>

#include <math.h>
#include <signal.h>

#ifndef WIN32
#include <sys/wait.h>
#endif

#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

#include <osquery/config/config.h>
#include <osquery/core/shutdown.h>
#include <osquery/core/sql/query_data.h>
#include <osquery/core/watcher.h>
#include <osquery/extensions/extensions.h>
#include <osquery/filesystem/fileops.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/data_logger.h>
#include <osquery/logger/logger.h>
#include <osquery/process/process.h>
#include <osquery/sql/sql.h>

#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/info/tool_type.h>
#include <osquery/utils/system/time.h>

namespace fs = boost::filesystem;

namespace osquery {

struct LimitDefinition {
  size_t normal;
  size_t restrictive;
  size_t disabled;
};

struct PerformanceChange {
  size_t sustained_latency{0};
  uint64_t footprint{0};
  uint64_t iv{0};
  pid_t parent{0};
};

using WatchdogLimitMap = std::map<WatchdogLimitType, LimitDefinition>;

namespace {

const auto kNumOfCPUs = boost::thread::physical_concurrency();

const WatchdogLimitMap kWatchdogLimits = {
    // Maximum MB worker can privately allocate.
    {WatchdogLimitType::MEMORY_LIMIT, {200, 100, 10000}},

    // % of (User + System + Idle) CPU time worker can utilize
    // for LATENCY_LIMIT seconds.
    {WatchdogLimitType::UTILIZATION_LIMIT, {10, 5, 100}},

    // Number of seconds the worker should run, else consider the exit fatal.
    {WatchdogLimitType::RESPAWN_LIMIT, {4, 4, 1000}},

    // If the worker respawns too quickly, backoff on creating additional.
    {WatchdogLimitType::RESPAWN_DELAY, {5, 5, 1}},

    // Seconds of tolerable UTILIZATION_LIMIT sustained latency.
    {WatchdogLimitType::LATENCY_LIMIT, {12, 6, 1000}},

    // How often to poll for performance limit violations.
    {WatchdogLimitType::INTERVAL, {3, 3, 3}},
};

/// Set to true if at least one extension is watched.
std::atomic<bool> kExtensionsWatched{false};
} // namespace

CLI_FLAG(int32,
         watchdog_level,
         0,
         "Performance limit level (0=normal, 1=restrictive, -1=off)");

CLI_FLAG(uint64,
         watchdog_memory_limit,
         0,
         "Override watchdog profile memory limit (e.g., 300, for 300MB)");

CLI_FLAG(uint64,
         watchdog_utilization_limit,
         0,
         "Override watchdog profile CPU utilization limit");

CLI_FLAG(uint64,
         watchdog_latency_limit,
         0,
         "Override watchdog profile CPU utilization latency limit");

CLI_FLAG(uint64,
         watchdog_delay,
         60,
         "Initial delay in seconds before watchdog starts");

HIDDEN_FLAG(uint64,
            watchdog_max_delay,
            60 * 10,
            "Max delay in seconds between worker respawns");

CLI_FLAG(bool,
         enable_extensions_watchdog,
         false,
         "Enable userland watchdog for extensions processes");

CLI_FLAG(uint64,
         watchdog_forced_shutdown_delay,
         4,
         "Seconds that the watchdog will wait to do a forced shutdown after a "
         "graceful shutdown request, when a resource limit is hit");

CLI_FLAG(bool, disable_watchdog, false, "Disable userland watchdog process");

DECLARE_uint64(alarm_timeout);

void Watcher::resetWorkerCounters(uint64_t respawn_time) {
  // Reset the monitoring counters for the watcher.
  state_.sustained_latency = 0;
  state_.user_time = 0;
  state_.system_time = 0;
  state_.last_respawn_time = respawn_time;
}

void Watcher::resetExtensionCounters(const std::string& extension,
                                     uint64_t respawn_time) {
  auto& state = extension_states_[extension];
  state.sustained_latency = 0;
  state.user_time = 0;
  state.system_time = 0;
  state.last_respawn_time = respawn_time;
}

std::string Watcher::getExtensionPath(const PlatformProcess& child) {
  for (const auto& extension : extensions()) {
    if (*extension.second == child) {
      return extension.first;
    }
  }
  return "";
}

void Watcher::removeExtensionPath(const std::string& extension) {
  extensions_.erase(extension);
  extension_states_.erase(extension);
}

PerformanceState& Watcher::getState(const PlatformProcess& child) {
  if (child == getWorker()) {
    return state_;
  } else {
    return extension_states_[getExtensionPath(child)];
  }
}

PerformanceState& Watcher::getState(const std::string& extension) {
  return extension_states_[extension];
}

void Watcher::setExtension(const std::string& extension,
                           const std::shared_ptr<PlatformProcess>& child) {
  kExtensionsWatched = true;
  extensions_[extension] = child;
}

void Watcher::reset(const PlatformProcess& child) {
  std::unique_lock<std::mutex> lock(new_processes_mutex_);
  if (child == getWorker()) {
    worker_ = std::make_shared<PlatformProcess>();
    resetWorkerCounters(0);
    return;
  }

  // If it was not the worker pid then find the extension name to reset.
  for (const auto& extension : extensions()) {
    if (*extension.second == child) {
      setExtension(extension.first, std::make_shared<PlatformProcess>());
      resetExtensionCounters(extension.first, 0);
    }
  }
}

void Watcher::loadExtensions() {
  std::unique_lock<std::mutex> lock(new_processes_mutex_);
  auto autoload_paths = osquery::loadExtensions();
  for (const auto& path : autoload_paths) {
    setExtension(path, std::make_shared<PlatformProcess>());
    resetExtensionCounters(path, 0);
  }
}

bool Watcher::hasManagedExtensions() {
  if (kExtensionsWatched) {
    return true;
  }

  // A watchdog process may hint to a worker the number of managed extensions.
  // Setting this counter to 0 will prevent the worker from waiting for missing
  // dependent config plugins. Otherwise, its existence, will cause a worker to
  // wait for missing plugins to broadcast from managed extensions.
  return getEnvVar("OSQUERY_EXTENSIONS").is_initialized();
}

WatcherRunner::WatcherRunner(int argc,
                             char** argv,
                             bool use_worker,
                             const std::shared_ptr<Watcher>& watcher)
    : InternalRunnable("WatcherRunner"),
      argc_(argc),
      argv_(argv),
      use_worker_(use_worker),
      watcher_(watcher) {}

bool WatcherRunner::ok() const {
  // Inspect the exit code, on success or catastrophic, end the watcher.
  auto status = watcher_->getWorkerStatus();
  if (status == EXIT_SUCCESS || status == EXIT_CATASTROPHIC) {
    return false;
  }
  // Watcher is OK to run if a worker or at least one extension exists.
  return (watcher_->getWorker().isValid() || watcher_->hasManagedExtensions());
}

void WatcherRunner::start() {
  // Hold the current process (watcher) for inspection too.
  auto self = PlatformProcess::getCurrentProcess();

  // Set worker performance counters to an initial state.
  watcher_->resetWorkerCounters(0);
  PerformanceState watcher_state;

  // Enter the watch loop.
  do {
    if (use_worker_ && !watch(watcher_->getWorker())) {
      if (watcher_->fatesBound()) {
        // A signal has interrupted the watcher.
        break;
      }

      auto status = watcher_->getWorkerStatus();
      if (status == EXIT_CATASTROPHIC) {
        requestShutdown(EXIT_CATASTROPHIC, "Worker returned exit status");
        break;
      }

      if (watcher_->workerRestartCount() ==
          getWorkerLimit(WatchdogLimitType::RESPAWN_LIMIT)) {
        // Too many worker restarts.
        requestShutdown(EXIT_FAILURE, "Too many worker restarts");
        break;
      }

      // The watcher failed, create a worker.
      createWorker();

      // The createWorker function can request a shutdown on error,
      // or be interrupted by a stop request, do not continue if that happens.
      if (interrupted() || shutdownRequested()) {
        break;
      }
    }

    // After inspecting the worker, check the extensions.
    // Extensions may be active even if a worker/watcher is not used.
    watchExtensions();

    if (use_worker_) {
      auto status = isWatcherHealthy(*self, watcher_state);
      if (!status.ok()) {
        requestShutdown(EXIT_CATASTROPHIC,
                        "Watcher has become unhealthy: " + status.getMessage());
        break;
      }
    }

    if (run_once_) {
      // A test harness can end the thread immediately.
      break;
    }
    pause(std::chrono::seconds(getWorkerLimit(WatchdogLimitType::INTERVAL)));
  } while (!interrupted() && ok());
}

void WatcherRunner::stop() {
  std::unique_lock<std::mutex> lock(watcher_->new_processes_mutex_);

  auto stop_extension = [this](
                            const std::string& extension_name,
                            const std::shared_ptr<PlatformProcess> extension) {
    try {
      stopChild(*extension);
    } catch (std::exception& e) {
      LOG(ERROR) << "[WatcherRunner] couldn't kill the extension "
                 << extension_name << "nicely. Reason: " << e.what()
                 << std::endl;
      extension->kill();
    }
  };

  std::vector<std::thread> stop_extensions_threads;
  for (const auto& extension : watcher_->extensions()) {
    stop_extensions_threads.emplace_back(
        stop_extension, extension.first, extension.second);
  }

  auto& worker = watcher_->getWorker();
  if (worker.isValid()) {
    stopChild(worker);
  }

  for (auto& thread : stop_extensions_threads) {
    thread.join();
  }
}

void WatcherRunner::watchExtensions() {
  // Loop over every managed extension and check sanity.
  for (const auto& extension : watcher_->extensions()) {
    // Check the extension status, causing a wait.
    int process_status = 0;
    ProcessState status = extension.second->checkStatus(process_status);

    bool ext_valid = (PROCESS_STILL_ALIVE == status);

    // If the extension is alive and watched, check sanity
    if (ext_valid && FLAGS_enable_extensions_watchdog) {
      if (getUnixTime() < delayedTime()) {
        return;
      }
      auto s = isChildSane(*extension.second);
      if (!s.ok()) {
        std::stringstream error;
        error << "osquery extension " << extension.first << " ("
              << extension.second->pid() << ") stopping: " << s.getMessage();
        systemLog(error.str());
        LOG(WARNING) << error.str();
        stopChild(*extension.second, true);
        pause(
            std::chrono::seconds(getWorkerLimit(WatchdogLimitType::INTERVAL)));
        ext_valid = false;
      }
    }

    if (!ext_valid) {
      // The extension manager also watches for extension-related failures.
      // The watchdog is more general, but may find failed extensions first.
      createExtension(extension.first);
      extension_restarts_[extension.first] += 1;
    } else {
      extension_restarts_[extension.first] = 0;
    }
  }
}

uint64_t WatcherRunner::delayedTime() const {
  return watcher_->workerStartTime() + FLAGS_watchdog_delay;
}

bool WatcherRunner::watch(const PlatformProcess& child) const {
  int process_status = 0;
  ProcessState result = child.checkStatus(process_status);
  if (watcher_->fatesBound()) {
    // A signal was handled while the watcher was watching.
    return false;
  }

  if (!child.isValid() || result == PROCESS_ERROR) {
    // Worker does not exist or never existed.
    return false;
  } else if (result == PROCESS_STILL_ALIVE) {
    // If the inspect finds problems it will stop/restart the worker.
    auto status = isChildSane(child);
    // A delayed watchdog does not stop the worker process.
    if (!status.ok() && getUnixTime() >= delayedTime()) {
      // Since the watchdog cannot use the logger plugin the error message
      // should be logged to stderr and to the system log.
      std::stringstream error;
      error << "osqueryd worker (" << child.pid()
            << ") stopping: " << status.getMessage();
      systemLog(error.str());
      LOG(WARNING) << error.str();
      warnWorkerResourceLimitHit(child);
      stopChild(child, true);
      return false;
    }
    return true;
  }

  if (result == PROCESS_EXITED) {
    // If the worker process existed, store the exit code.
    watcher_->worker_status_ = process_status;
    return false;
  }

  return true;
}

void WatcherRunner::stopChild(const PlatformProcess& child, bool force) const {
  auto child_pid = child.pid();

  /* In the normal shutdown case we use alarm_timeout,
     we leave 2 seconds for the rest of the logic to shutdown,
     and 2 seconds for the forced kill to do the reaping.
     Otherwise use the forced shutdown timeout directly */
  auto timeout = (force ? FLAGS_watchdog_forced_shutdown_delay
                        : (FLAGS_alarm_timeout - 4)) *
                 1000;

  // Attempt a clean shutdown
  if (timeout > 0) {
    child.killGracefully();

    // Clean up the defunct (zombie) process.
    if (child.cleanup(std::chrono::milliseconds(timeout))) {
      // The process exited cleanly
      return;
    }

    LOG(WARNING) << "osqueryd worker (" << std::to_string(child_pid)
                 << ") could not be stopped. Sending kill signal.";
  }

  // If the process hasn't exited cleanly yet, or we need to immediately kill
  // a misbehaving worker/extension, send a kill signal
  child.kill();
  if (!child.cleanup(std::chrono::milliseconds(2000))) {
    auto message = std::string("Watcher cannot stop worker process (") +
                   std::to_string(child_pid) + ").";
    requestShutdown(EXIT_CATASTROPHIC, message);
  }
}

void WatcherRunner::warnWorkerResourceLimitHit(
    const PlatformProcess& child) const {
  child.warnResourceLimitHit();
}

PerformanceChange getChange(const Row& r, PerformanceState& state) {
  PerformanceChange change;

  // IV is the check interval in seconds, and utilization is set per-second.
  change.iv = std::max(getWorkerLimit(WatchdogLimitType::INTERVAL), 1_sz);
  long long user_time = 0, system_time = 0;
  try {
    change.parent =
        static_cast<pid_t>(tryTo<long long>(r.at("parent")).takeOr(0LL));
    user_time = tryTo<long long>(r.at("user_time")).takeOr(0LL);
    system_time = tryTo<long long>(r.at("system_time")).takeOr(0LL);
    if (isPlatform(PlatformType::TYPE_WINDOWS)) {
      change.footprint = tryTo<long long>(r.at("total_size")).takeOr(0LL);
    } else {
      change.footprint = tryTo<long long>(r.at("resident_size")).takeOr(0LL);
    }
  } catch (const std::exception& /* e */) {
    state.sustained_latency = 0;
  }

  // Check the difference of CPU time used since last check.
  auto percent_ul = getWorkerLimit(WatchdogLimitType::UTILIZATION_LIMIT);
  percent_ul = (percent_ul > 100) ? 100 : percent_ul;

  UNSIGNED_BIGINT_LITERAL iv_milliseconds = change.iv * 1000;
  UNSIGNED_BIGINT_LITERAL cpu_ul =
      (percent_ul * iv_milliseconds * kNumOfCPUs) / 100;

  auto user_time_diff = user_time - state.user_time;
  auto sys_time_diff = system_time - state.system_time;
  UNSIGNED_BIGINT_LITERAL cpu_utilization_time = user_time_diff + sys_time_diff;

  if (cpu_utilization_time > cpu_ul) {
    state.sustained_latency++;
  } else {
    state.sustained_latency = 0;
  }
  // Update the current CPU time.
  state.user_time = user_time;
  state.system_time = system_time;

  // Check if the sustained difference exceeded the acceptable latency limit.
  change.sustained_latency = state.sustained_latency;

  // Set the memory footprint as the amount of resident bytes allocated
  // since the process image was created (estimate).
  // A more-meaningful check would limit this to writable regions.
  if (state.initial_footprint == 0) {
    state.initial_footprint = change.footprint;
  }

  // Set the measured/limit-applied footprint to the post-launch allocations.
  if (change.footprint < state.initial_footprint) {
    change.footprint = 0;
  } else {
    change.footprint = change.footprint - state.initial_footprint;
  }

  return change;
}

static bool exceededMemoryLimit(const PerformanceChange& change) {
  if (change.footprint == 0) {
    return false;
  }

  return (change.footprint >
          getWorkerLimit(WatchdogLimitType::MEMORY_LIMIT) * 1024 * 1024);
}

static bool exceededCyclesLimit(const PerformanceChange& change) {
  if (change.sustained_latency == 0) {
    return false;
  }

  auto latency = change.sustained_latency * change.iv;
  return (latency >= getWorkerLimit(WatchdogLimitType::LATENCY_LIMIT));
}

Status WatcherRunner::isWatcherHealthy(const PlatformProcess& watcher,
                                       PerformanceState& watcher_state) const {
  auto rows = getProcessRow(watcher.pid());
  if (rows.size() == 0) {
    // Could not find worker process?
    return Status(1, "Cannot find watcher process");
  }

  auto change = getChange(rows[0], watcher_state);
  if (exceededMemoryLimit(change)) {
    return Status(1, "Memory limits exceeded");
  }

  return Status(0);
}

QueryData WatcherRunner::getProcessRow(pid_t pid) const {
  // On Windows, pid_t = DWORD, which is unsigned. However invalidity
  // of processes is denoted by a pid_t of -1. We check for this
  // by comparing the max value of DWORD, or ULONG_MAX, and then casting
  // our query back to an int value, as ULONG_MAX causes boost exceptions
  // as it's out of the range of an int.
  int p = pid;
#ifdef WIN32
  p = (pid == ULONG_MAX) ? -1 : pid;
#endif
  return SQL::selectFrom(
      {"parent", "user_time", "system_time", "resident_size", "total_size"},
      "processes",
      "pid",
      EQUALS,
      INTEGER(p));
}

Status WatcherRunner::isChildSane(const PlatformProcess& child) const {
  auto rows = getProcessRow(child.pid());
  if (rows.size() == 0) {
    // Could not find worker process?
    return Status(1, "Cannot find process");
  }

  PerformanceChange change;
  {
    auto& state = watcher_->getState(child);
    change = getChange(rows[0], state);
  }

  // Only make a decision about the child sanity if it is still the watcher's
  // child. It's possible for the child to die, and its pid reused.
  if (change.parent != PlatformProcess::getCurrentPid()) {
    // The child's parent is not the watcher.
    watcher_->reset(child);
    // Do not stop or call the child insane, since it is not our child.
    return Status(0);
  }

  if (exceededCyclesLimit(change)) {
    return Status(1,
                  "Maximum sustainable CPU utilization limit exceeded: " +
                      std::to_string(change.sustained_latency * change.iv));
  }

  // Check if the private memory exceeds a memory limit.
  if (exceededMemoryLimit(change)) {
    return Status(
        1, "Memory limits exceeded: " + std::to_string(change.footprint));
  }

  // The worker is sane, no action needed.
  // Attempt to flush status logs to the well-behaved worker.
  if (use_worker_ && child.pid() == watcher_->getWorker().pid()) {
    relayStatusLogs();
  }

  return Status(0);
}

void WatcherRunner::createWorker() {
  std::unique_lock<std::mutex> lock(watcher_->new_processes_mutex_);

  // A stop request can arrive from a different thread,
  // we should therefore avoid to launch a worker
  // that will be immediately stopped.
  if (interrupted()) {
    return;
  }

  watcher_->workerStartTime(getUnixTime());

  if (watcher_->getState(watcher_->getWorker()).last_respawn_time >
      getUnixTime() - getWorkerLimit(WatchdogLimitType::RESPAWN_LIMIT)) {
    watcher_->workerRestarted();
    LOG(WARNING) << "osqueryd worker respawning too quickly: "
                 << watcher_->workerRestartCount() << " times";

    // The configured automatic delay.
    uint64_t delay = getWorkerLimit(WatchdogLimitType::RESPAWN_DELAY);
    // Exponential back off for quickly-respawning clients.
    delay += static_cast<size_t>(pow(2, watcher_->workerRestartCount()));
    delay = std::min(static_cast<uint64_t>(FLAGS_watchdog_max_delay), delay);
    pause(std::chrono::seconds(delay));
  }

  // Get the path of the current process.
  auto qd = SQL::selectFrom({"path"},
                            "processes",
                            "pid",
                            EQUALS,
                            INTEGER(PlatformProcess::getCurrentPid()));
  if (qd.size() != 1 || qd[0].count("path") == 0 || qd[0]["path"].size() == 0) {
    requestShutdown(EXIT_FAILURE,
                    "osquery watcher cannot determine process path for worker");
    return;
  }

  // Set an environment signaling to potential plugin-dependent workers to wait
  // for extensions to broadcast.
  if (Watcher::hasManagedExtensions()) {
    setEnvVar("OSQUERY_EXTENSIONS", "true");
  }

  // Get the complete path of the osquery process binary.
  boost::system::error_code ec;
  auto exec_path = fs::system_complete(fs::path(qd[0]["path"]), ec);
  if (!pathExists(exec_path).ok()) {
    LOG(WARNING) << "osqueryd doesn't exist in: " << exec_path.string();
    return;
  }
  if (!safePermissions(
          exec_path.parent_path().string(), exec_path.string(), true)) {
    // osqueryd binary has become unsafe.
    auto message = std::string(RLOG(1382)) +
                   "osqueryd has unsafe permissions: " + exec_path.string();
    requestShutdown(EXIT_FAILURE, message);
    return;
  }

  auto worker = PlatformProcess::launchWorker(exec_path.string(), argc_, argv_);
  if (worker == nullptr) {
    // Unrecoverable error, cannot create a worker process.
    LOG(ERROR) << "osqueryd could not create a worker process";
    requestShutdown(EXIT_FAILURE);
    return;
  }

  watcher_->setWorker(worker);
  watcher_->resetWorkerCounters(getUnixTime());
  VLOG(1) << "osqueryd watcher (" << PlatformProcess::getCurrentPid()
          << ") executing worker (" << worker->pid() << ")";
  watcher_->worker_status_ = -1;
}

void WatcherRunner::createExtension(const std::string& extension) {
  std::unique_lock<std::mutex> lock(watcher_->new_processes_mutex_);

  // A stop request can arrive from a different thread,
  // we should therefore avoid to launch an extension
  // that will be immediately stopped.
  if (interrupted()) {
    return;
  }

  {
    if (watcher_->getState(extension).last_respawn_time >
        getUnixTime() - getWorkerLimit(WatchdogLimitType::RESPAWN_LIMIT)) {
      LOG(WARNING) << "Extension respawning too quickly: " << extension;
      // Unlike a worker, if an extension respawns to quickly we give up.
    }
  }

  // Check the path to the previously-discovered extension binary.
  boost::system::error_code ec;
  auto exec_path = fs::system_complete(fs::path(extension), ec);
  if (!pathExists(exec_path).ok()) {
    LOG(WARNING) << "Extension binary doesn't exist in: " << exec_path.string();
    return;
  }
  if (!safePermissions(
          exec_path.parent_path().string(), exec_path.string(), true)) {
    // Extension binary has become unsafe.
    LOG(WARNING) << RLOG(1382)
                 << "Extension binary has unsafe permissions: " << extension;
    return;
  }

  auto ext_process =
      PlatformProcess::launchExtension(exec_path.string(),
                                       Flag::getValue("extensions_socket"),
                                       Flag::getValue("extensions_timeout"),
                                       Flag::getValue("extensions_interval"),
                                       Flag::getValue("verbose") == "true");
  if (ext_process == nullptr) {
    // Unrecoverable error, cannot create an extension process.
    LOG(ERROR) << "Cannot create extension process: " << extension;
    requestShutdown(EXIT_FAILURE);
  }

  watcher_->setExtension(extension, ext_process);
  watcher_->resetExtensionCounters(extension, getUnixTime());
  VLOG(1) << "Created and monitoring extension child (" << ext_process->pid()
          << "): " << extension;
}

void WatcherWatcherRunner::start() {
  while (!interrupted()) {
    if (isLauncherProcessDead(*watcher_)) {
      // Watcher died, the worker must follow.
      VLOG(1) << "osqueryd worker (" << PlatformProcess::getCurrentPid()
              << ") detected killed watcher (" << watcher_->pid() << ")";
      // The watcher watcher is a thread. Do not join services after removing.
      requestShutdown();
      break;
    }
    pause(std::chrono::seconds(getWorkerLimit(WatchdogLimitType::INTERVAL)));
  }
}

uint64_t getWorkerLimit(WatchdogLimitType name) {
  if (kWatchdogLimits.count(name) == 0) {
    return 0;
  }

  if (name == WatchdogLimitType::MEMORY_LIMIT &&
      FLAGS_watchdog_memory_limit > 0) {
    return FLAGS_watchdog_memory_limit;
  }

  if (name == WatchdogLimitType::UTILIZATION_LIMIT &&
      FLAGS_watchdog_utilization_limit > 0) {
    return FLAGS_watchdog_utilization_limit;
  }

  if (name == WatchdogLimitType::LATENCY_LIMIT &&
      FLAGS_watchdog_latency_limit > 0) {
    return FLAGS_watchdog_latency_limit;
  }

  auto level = FLAGS_watchdog_level;
  // If no level was provided then use the default (config/switch).
  if (level == -1) {
    return kWatchdogLimits.at(name).disabled;
  }

  if (level == 1) {
    return kWatchdogLimits.at(name).restrictive;
  }
  return kWatchdogLimits.at(name).normal;
}
} // namespace osquery
