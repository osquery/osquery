/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <cstring>

#include <math.h>
#include <signal.h>

#ifndef WIN32
#include <sys/wait.h>
#endif

#include <boost/filesystem.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/system.h>

#include "osquery/core/process.h"
#include "osquery/core/watcher.h"

extern char** environ;

namespace fs = boost::filesystem;

namespace osquery {

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
    {WatchdogLimitType::MEMORY_LIMIT, {100, 50, 1000}},
    // User or system CPU worker can utilize for LATENCY_LIMIT seconds.
    {WatchdogLimitType::UTILIZATION_LIMIT, {90, 80, 1000}},
    // Number of seconds the worker should run, else consider the exit fatal.
    {WatchdogLimitType::RESPAWN_LIMIT, {20, 20, 1000}},
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
         "Override watchdog profile memory limit");

CLI_FLAG(uint64,
         watchdog_utilization_limit,
         0,
         "Override watchdog profile CPU utilization limit");

CLI_FLAG(bool, disable_watchdog, false, "Disable userland watchdog process");

void Watcher::resetWorkerCounters(size_t respawn_time) {
  // Reset the monitoring counters for the watcher.
  auto& state = instance().state_;
  state.sustained_latency = 0;
  state.user_time = 0;
  state.system_time = 0;
  state.last_respawn_time = respawn_time;
}

void Watcher::resetExtensionCounters(const std::string& extension,
                                     size_t respawn_time) {
  WatcherLocker locker;
  auto& state = instance().extension_states_[extension];
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
  WatcherLocker locker;
  auto& self = instance();
  self.extensions_.erase(extension);
  self.extension_states_.erase(extension);
}

PerformanceState& Watcher::getState(const PlatformProcess& child) {
  auto& self = instance();
  if (child == *self.worker_) {
    return self.state_;
  } else {
    return self.extension_states_[getExtensionPath(child)];
  }
}

PerformanceState& Watcher::getState(const std::string& extension) {
  return instance().extension_states_[extension];
}

void Watcher::setExtension(const std::string& extension,
                           const std::shared_ptr<PlatformProcess>& child) {
  WatcherLocker locker;
  instance().extensions_[extension] = child;
}

void Watcher::reset(const PlatformProcess& child) {
  if (child == *instance().worker_) {
    instance().worker_ = 0;
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

bool Watcher::hasManagedExtensions() {
  if (instance().extensions_.size() > 0) {
    return true;
  }

  // A watchdog process may hint to a worker the number of managed extensions.
  // Setting this counter to 0 will prevent the worker from waiting for missing
  // dependent config plugins. Otherwise, its existence, will cause a worker to
  // wait for missing plugins to broadcast from managed extensions.
  return getEnvVar("OSQUERY_EXTENSIONS").is_initialized();
}

bool WatcherRunner::ok() {
  // Inspect the exit code, on success or catastrophic, end the watcher.
  auto status = Watcher::getWorkerStatus();
  if (status == EXIT_SUCCESS || status == EXIT_CATASTROPHIC) {
    return false;
  }
  // Watcher is OK to run if a worker or at least one extension exists.
  return (Watcher::getWorker().isValid() || Watcher::hasManagedExtensions());
}

void WatcherRunner::start() {
  // Set worker performance counters to an initial state.
  Watcher::resetWorkerCounters(0);
  // Hold the current process (watcher) for inspection too.
  auto watcher = PlatformProcess::getCurrentProcess();
  PerformanceState watcher_state;

  // Enter the watch loop.
  do {
    if (use_worker_ && !watch(Watcher::getWorker())) {
      if (Watcher::fatesBound()) {
        // A signal has interrupted the watcher.
        break;
      }
      // The watcher failed, create a worker.
      createWorker();
    }

    // Loop over every managed extension and check sanity.
    for (const auto& extension : Watcher::extensions()) {
      if (!isChildSane(*extension.second)) {
        // The extension manager also watches for extension-related failures.
        // The watchdog is more general, but may find failed extensions first.
        createExtension(extension.first);
        extension_restarts_[extension.first] += 1;
      } else {
        extension_restarts_[extension.first] = 0;
      }
    }
    // If any extension creations failed, stop managing them.
    for (auto& extension : extension_restarts_) {
      if (extension.second > 3) {
        Watcher::removeExtensionPath(extension.first);
        extension.second = 0;
      }
    }

    if (use_worker_) {
      auto status = isWatcherHealthy(*watcher, watcher_state);
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

bool WatcherRunner::watch(const PlatformProcess& child) const {
  int process_status = 0;
  ProcessState result = child.checkStatus(process_status);
  if (Watcher::fatesBound()) {
    // A signal was handled while the watcher was watching.
    return false;
  }

  if (!child.isValid() || result == PROCESS_ERROR) {
    // Worker does not exist or never existed.
    return false;
  } else if (result == PROCESS_STILL_ALIVE) {
    // If the inspect finds problems it will stop/restart the worker.
    auto status = isChildSane(child);
    if (!status.ok()) {
      LOG(WARNING) << "osqueryd worker (" << child.pid()
                   << "): " << status.getMessage();
      stopChild(child);
      return false;
    }
    return true;
  }

  if (result == PROCESS_EXITED) {
    // If the worker process existed, store the exit code.
    Watcher::instance().worker_status_ = process_status;
  }

  return true;
}

void WatcherRunner::stopChild(const PlatformProcess& child) const {
  child.killGracefully();

  // Clean up the defunct (zombie) process.
  if (!child.cleanup()) {
    // The child did not exit, force kill and attempt to cleanup again.
    child.kill();
    if (!child.cleanup()) {
      Initializer::requestShutdown(EXIT_CATASTROPHIC,
                                   "Watcher cannot stop worker process");
    }
  }
}

PerformanceChange getChange(const Row& r, PerformanceState& state) {
  PerformanceChange change;

  // IV is the check interval in seconds, and utilization is set per-second.
  change.iv = std::max(getWorkerLimit(WatchdogLimitType::INTERVAL), (size_t)1);
  UNSIGNED_BIGINT_LITERAL user_time = 0, system_time = 0;
  try {
    change.parent =
        static_cast<pid_t>(AS_LITERAL(BIGINT_LITERAL, r.at("parent")));
    user_time = AS_LITERAL(BIGINT_LITERAL, r.at("user_time")) / change.iv;
    system_time = AS_LITERAL(BIGINT_LITERAL, r.at("system_time")) / change.iv;
    change.footprint = AS_LITERAL(BIGINT_LITERAL, r.at("resident_size"));
  } catch (const std::exception& /* e */) {
    state.sustained_latency = 0;
  }

  // Check the difference of CPU time used since last check.
  if (user_time - state.user_time >
          getWorkerLimit(WatchdogLimitType::UTILIZATION_LIMIT) ||
      system_time - state.system_time >
          getWorkerLimit(WatchdogLimitType::UTILIZATION_LIMIT)) {
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
  return SQL::selectAllFrom("processes", "pid", EQUALS, INTEGER(pid));
}

Status WatcherRunner::isChildSane(const PlatformProcess& child) const {
  auto rows = getProcessRow(child.pid());
  if (rows.size() == 0) {
    // Could not find worker process?
    return Status(1, "Cannot find worker process");
  }

  PerformanceChange change;
  {
    WatcherLocker locker;
    auto& state = Watcher::getState(child);
    change = getChange(rows[0], state);
  }

  // Only make a decision about the child sanity if it is still the watcher's
  // child. It's possible for the child to die, and its pid reused.
  if (change.parent != PlatformProcess::getCurrentProcess()->pid()) {
    // The child's parent is not the watcher.
    Watcher::reset(child);
    // Do not stop or call the child insane, since it is not our child.
    return Status(0);
  }

  if (exceededCyclesLimit(change)) {
    return Status(1, "System performance limits exceeded");
  }
  // Check if the private memory exceeds a memory limit.
  if (exceededMemoryLimit(change)) {
    return Status(
        1, "Memory limits exceeded: " + std::to_string(change.footprint));
  }

  // The worker is sane, no action needed.
  // Attempt to flush status logs to the well-behaved worker.
  if (use_worker_ && child.pid() == Watcher::getWorker().pid()) {
    relayStatusLogs();
  }

  return Status(0);
}

void WatcherRunner::createWorker() {
  {
    WatcherLocker locker;
    if (Watcher::getState(Watcher::getWorker()).last_respawn_time >
        getUnixTime() - getWorkerLimit(WatchdogLimitType::RESPAWN_LIMIT)) {
      LOG(WARNING) << "osqueryd worker respawning too quickly: "
                   << Watcher::workerRestartCount() << " times";
      Watcher::workerRestarted();
      // The configured automatic delay.
      size_t delay = getWorkerLimit(WatchdogLimitType::RESPAWN_DELAY) * 1000;
      // Exponential back off for quickly-respawning clients.
      delay +=
          static_cast<size_t>(pow(2, Watcher::workerRestartCount())) * 1000;
      pauseMilli(delay);
    }
  }

  // Get the path of the current process.
  auto qd =
      SQL::selectAllFrom("processes",
                         "pid",
                         EQUALS,
                         INTEGER(PlatformProcess::getCurrentProcess()->pid()));
  if (qd.size() != 1 || qd[0].count("path") == 0 || qd[0]["path"].size() == 0) {
    LOG(ERROR) << "osquery watcher cannot determine process path for worker";
    Initializer::requestShutdown(EXIT_FAILURE);
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

  Watcher::setWorker(worker);
  Watcher::resetWorkerCounters(getUnixTime());
  VLOG(1) << "osqueryd watcher (" << PlatformProcess::getCurrentProcess()->pid()
          << ") executing worker (" << worker->pid() << ")";
}

void WatcherRunner::createExtension(const std::string& extension) {
  {
    WatcherLocker locker;
    if (Watcher::getState(extension).last_respawn_time >
        getUnixTime() - getWorkerLimit(WatchdogLimitType::RESPAWN_LIMIT)) {
      LOG(WARNING) << "Extension respawning too quickly: " << extension;
      // Unlike a worker, if an extension respawns to quickly we give up.
    }
  }

  // Check the path to the previously-discovered extension binary.
  boost::system::error_code ec;
  auto exec_path = fs::system_complete(fs::path(extension), ec);
  if (!safePermissions(
          exec_path.parent_path().string(), exec_path.string(), true)) {
    // Extension binary has become unsafe.
    LOG(WARNING) << RLOG(1382)
                 << "Extension binary has unsafe permissions: " << extension;
    return;
  }

  auto ext_process =
      PlatformProcess::launchExtension(exec_path.string(),
                                       extension,
                                       Flag::getValue("extensions_socket"),
                                       Flag::getValue("extensions_timeout"),
                                       Flag::getValue("extensions_interval"),
                                       Flag::getValue("verbose"));
  if (ext_process == nullptr) {
    // Unrecoverable error, cannot create an extension process.
    LOG(ERROR) << "Cannot create extension process: " << extension;
    Initializer::shutdown(EXIT_FAILURE);
  }

  Watcher::setExtension(extension, ext_process);
  Watcher::resetExtensionCounters(extension, getUnixTime());
  VLOG(1) << "Created and monitoring extension child (" << ext_process->pid()
          << "): " << extension;

}

void WatcherWatcherRunner::start() {
  while (!interrupted()) {
    if (isLauncherProcessDead(*watcher_)) {
      // Watcher died, the worker must follow.
      VLOG(1) << "osqueryd worker ("
              << PlatformProcess::getCurrentProcess()->pid()
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
}
