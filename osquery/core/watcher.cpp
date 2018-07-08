/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <cstring>

#include <math.h>
#include <signal.h>

#ifndef WIN32
#include <sys/wait.h>
#endif

#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

#include <osquery/config.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/system.h>

#include "osquery/core/process.h"
#include "osquery/core/watcher.h"
#include "osquery/filesystem/fileops.h"

namespace fs = boost::filesystem;

namespace osquery {

const auto kNumOfCPUs = boost::thread::physical_concurrency();

struct LimitDefinition {
  size_t normal;
  size_t restrictive;
  size_t disabled;
};

struct PerformanceChange {
  size_t sustained_latency;
  size_t footprint;
  size_t iv;
  pid_t parent;
};

using WatchdogLimitMap = std::map<WatchdogLimitType, LimitDefinition>;

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
         "Disable userland watchdog for extensions processes");

CLI_FLAG(bool, disable_watchdog, false, "Disable userland watchdog process");

void Watcher::resetWorkerCounters(size_t respawn_time) {
  // Reset the monitoring counters for the watcher.
  state_.sustained_latency = 0;
  state_.user_time = 0;
  state_.system_time = 0;
  state_.last_respawn_time = respawn_time;
}

void Watcher::resetExtensionCounters(const std::string& extension,
                                     size_t respawn_time) {
  WatcherExtensionsLocker locker;
  auto& state = get().extension_states_[extension];
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
  WatcherExtensionsLocker locker;
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
  WatcherExtensionsLocker locker;
  extensions_[extension] = child;
}

void Watcher::reset(const PlatformProcess& child) {
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

void Watcher::addExtensionPath(const std::string& path) {
  setExtension(path, std::make_shared<PlatformProcess>());
  resetExtensionCounters(path, 0);
}

bool Watcher::hasManagedExtensions() const {
  if (!extensions_.empty()) {
    return true;
  }

  // A watchdog process may hint to a worker the number of managed extensions.
  // Setting this counter to 0 will prevent the worker from waiting for missing
  // dependent config plugins. Otherwise, its existence, will cause a worker to
  // wait for missing plugins to broadcast from managed extensions.
  return getEnvVar("OSQUERY_EXTENSIONS").is_initialized();
}

bool WatcherRunner::ok() const {
  // Inspect the exit code, on success or catastrophic, end the watcher.
  auto status = Watcher::get().getWorkerStatus();
  if (status == EXIT_SUCCESS || status == EXIT_CATASTROPHIC) {
    return false;
  }
  // Watcher is OK to run if a worker or at least one extension exists.
  return (Watcher::get().getWorker().isValid() ||
          Watcher::get().hasManagedExtensions());
}

void WatcherRunner::start() {
  // Hold the current process (watcher) for inspection too.
  auto& watcher = Watcher::get();
  auto self = PlatformProcess::getCurrentProcess();

  // Set worker performance counters to an initial state.
  watcher.resetWorkerCounters(0);
  PerformanceState watcher_state;

  // Enter the watch loop.
  do {
    if (use_worker_ && !watch(watcher.getWorker())) {
      if (watcher.fatesBound()) {
        // A signal has interrupted the watcher.
        break;
      }

      auto status = watcher.getWorkerStatus();
      if (status == EXIT_CATASTROPHIC) {
        Initializer::requestShutdown(EXIT_CATASTROPHIC);
        break;
      }

      if (watcher.workerRestartCount() ==
          getWorkerLimit(WatchdogLimitType::RESPAWN_LIMIT)) {
        // Too many worker restarts.
        Initializer::requestShutdown(EXIT_FAILURE, "Too many worker restarts");
        break;
      }

      // The watcher failed, create a worker.
      createWorker();
    }

    // After inspecting the worker, check the extensions.
    // Extensions may be active even if a worker/watcher is not used.
    watchExtensions();

    if (use_worker_) {
      auto status = isWatcherHealthy(*self, watcher_state);
      if (!status.ok()) {
        Initializer::requestShutdown(
            EXIT_CATASTROPHIC,
            "Watcher has become unhealthy: " + status.getMessage());
        break;
      }
    }

    if (run_once_) {
      // A test harness can end the thread immediately.
      break;
    }
    pauseMilli(getWorkerLimit(WatchdogLimitType::INTERVAL) * 1000);
  } while (!interrupted() && ok());
}

void WatcherRunner::stop() {
  auto& watcher = Watcher::get();

  for (const auto& extension : watcher.extensions()) {
    try {
      stopChild(*extension.second);
    } catch (std::exception& e) {
      LOG(ERROR) << "[WatcherRunner] couldn't kill the extension "
                 << extension.first << "nicely. Reason: " << e.what()
                 << std::endl;
      extension.second->kill();
    }
  }
}

void WatcherRunner::watchExtensions() {
  auto& watcher = Watcher::get();

  // Loop over every managed extension and check sanity.
  for (const auto& extension : watcher.extensions()) {
    // Check the extension status, causing a wait.
    int process_status = 0;
    extension.second->checkStatus(process_status);

    auto ext_valid = extension.second->isValid();
    auto s = isChildSane(*extension.second);

    if (!ext_valid || (!s.ok() && getUnixTime() >= delayedTime())) {
      if (ext_valid && FLAGS_enable_extensions_watchdog) {
        // The extension was already launched once.
        std::stringstream error;
        error << "osquery extension " << extension.first << " ("
              << extension.second->pid() << ") stopping: " << s.getMessage();
        systemLog(error.str());
        LOG(WARNING) << error.str();
        stopChild(*extension.second);
        pauseMilli(getWorkerLimit(WatchdogLimitType::INTERVAL) * 1000);
      }

      // The extension manager also watches for extension-related failures.
      // The watchdog is more general, but may find failed extensions first.
      createExtension(extension.first);
      extension_restarts_[extension.first] += 1;
    } else {
      extension_restarts_[extension.first] = 0;
    }
  }
}

size_t WatcherRunner::delayedTime() const {
  return Config::getStartTime() + FLAGS_watchdog_delay;
}

bool WatcherRunner::watch(const PlatformProcess& child) const {
  int process_status = 0;
  ProcessState result = child.checkStatus(process_status);
  if (Watcher::get().fatesBound()) {
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
      stopChild(child);
      return false;
    }
    return true;
  }

  if (result == PROCESS_EXITED) {
    // If the worker process existed, store the exit code.
    Watcher::get().worker_status_ = process_status;
    return false;
  }

  return true;
}

void WatcherRunner::stopChild(const PlatformProcess& child) const {
  child.killGracefully();

  // Clean up the defunct (zombie) process.
  if (!child.cleanup()) {
    auto child_pid = child.pid();

    LOG(WARNING) << "osqueryd worker (" << std::to_string(child_pid)
                 << ") could not be stopped. Sending kill signal.";

    child.kill();
    if (!child.cleanup()) {
      auto message = std::string("Watcher cannot stop worker process (") +
                     std::to_string(child_pid) + ").";
      Initializer::requestShutdown(EXIT_CATASTROPHIC, message);
    }
  }
}

PerformanceChange getChange(const Row& r, PerformanceState& state) {
  PerformanceChange change;

  // IV is the check interval in seconds, and utilization is set per-second.
  change.iv = std::max(getWorkerLimit(WatchdogLimitType::INTERVAL), 1_sz);
  UNSIGNED_BIGINT_LITERAL user_time = 0, system_time = 0;
  try {
<<<<<<< Updated upstream
    change.parent =
        static_cast<pid_t>(AS_LITERAL(BIGINT_LITERAL, r.at("parent")));
    user_time = AS_LITERAL(BIGINT_LITERAL, r.at("user_time"));
    system_time = AS_LITERAL(BIGINT_LITERAL, r.at("system_time"));
    change.footprint = AS_LITERAL(BIGINT_LITERAL, r.at("resident_size"));
=======
    change.parent = static_cast<pid_t>(std::stoll(r.at("parent")));
    user_time = std::stoll(r.at("user_time")) / change.iv;
    system_time = std::stoll(r.at("system_time")) / change.iv;
    change.footprint = std::stoll(r.at("resident_size"));
>>>>>>> Stashed changes
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
  auto cpu_utilization_time = user_time_diff + sys_time_diff;

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
      {"parent", "user_time", "system_time", "resident_size"},
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
    WatcherExtensionsLocker locker;
    auto& state = Watcher::get().getState(child);
    change = getChange(rows[0], state);
  }

  // Only make a decision about the child sanity if it is still the watcher's
  // child. It's possible for the child to die, and its pid reused.
  if (change.parent != PlatformProcess::getCurrentPid()) {
    // The child's parent is not the watcher.
    Watcher::get().reset(child);
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
  if (use_worker_ && child.pid() == Watcher::get().getWorker().pid()) {
    relayStatusLogs();
  }

  return Status(0);
}

void WatcherRunner::createWorker() {
  auto& watcher = Watcher::get();

  {
    WatcherExtensionsLocker locker;
    if (watcher.getState(watcher.getWorker()).last_respawn_time >
        getUnixTime() - getWorkerLimit(WatchdogLimitType::RESPAWN_LIMIT)) {
      watcher.workerRestarted();
      LOG(WARNING) << "osqueryd worker respawning too quickly: "
                   << watcher.workerRestartCount() << " times";

      // The configured automatic delay.
      size_t delay = getWorkerLimit(WatchdogLimitType::RESPAWN_DELAY);
      // Exponential back off for quickly-respawning clients.
      delay += static_cast<size_t>(pow(2, watcher.workerRestartCount()));
      delay = std::min(static_cast<size_t>(FLAGS_watchdog_max_delay), delay);
      pauseMilli(delay * 1000);
    }
  }

  // Get the path of the current process.
  auto qd = SQL::selectFrom({"path"},
                            "processes",
                            "pid",
                            EQUALS,
                            INTEGER(PlatformProcess::getCurrentPid()));
  if (qd.size() != 1 || qd[0].count("path") == 0 || qd[0]["path"].size() == 0) {
    LOG(ERROR) << "osquery watcher cannot determine process path for worker";
    Initializer::requestShutdown(EXIT_FAILURE);
    return;
  }

  // Set an environment signaling to potential plugin-dependent workers to wait
  // for extensions to broadcast.
  if (watcher.hasManagedExtensions()) {
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
    LOG(ERROR) << RLOG(1382)
               << "osqueryd has unsafe permissions: " << exec_path.string();
    Initializer::requestShutdown(EXIT_FAILURE);
    return;
  }

  auto worker = PlatformProcess::launchWorker(exec_path.string(), argc_, argv_);
  if (worker == nullptr) {
    // Unrecoverable error, cannot create a worker process.
    LOG(ERROR) << "osqueryd could not create a worker process";
    Initializer::shutdown(EXIT_FAILURE);
    return;
  }

  watcher.setWorker(worker);
  watcher.resetWorkerCounters(getUnixTime());
  VLOG(1) << "osqueryd watcher (" << PlatformProcess::getCurrentPid()
          << ") executing worker (" << worker->pid() << ")";
  watcher.worker_status_ = -1;
}

void WatcherRunner::createExtension(const std::string& extension) {
  auto& watcher = Watcher::get();

  {
    WatcherExtensionsLocker locker;
    if (watcher.getState(extension).last_respawn_time >
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
    Initializer::shutdown(EXIT_FAILURE);
  }

  watcher.setExtension(extension, ext_process);
  watcher.resetExtensionCounters(extension, getUnixTime());
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
      Initializer::requestShutdown();
      break;
    }
    pauseMilli(getWorkerLimit(WatchdogLimitType::INTERVAL) * 1000);
  }
}

size_t getWorkerLimit(WatchdogLimitType name) {
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
