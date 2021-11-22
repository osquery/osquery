/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/shutdown.h>
#include <osquery/logger/data_logger.h>

#include <atomic>
#include <mutex>
#include <string>

namespace osquery {

namespace {

struct ShutdownData {
  /// The main thread can wait for a request from anywhere in the codebase.
  std::condition_variable request_signal;

  /// Mutex for the request signal.
  std::mutex request_mutex;

  /// A request to shutdown may only be issued once.
  std::atomic<bool> requested{false};

  /// The current requested return code for the process.
  std::sig_atomic_t retcode{0};
};

struct ShutdownData kShutdownData;
} // namespace

bool shutdownRequested() {
  return kShutdownData.requested;
}

int getShutdownExitCode() {
  return kShutdownData.retcode;
}

void setShutdownExitCode(int retcode) {
  kShutdownData.retcode = retcode;
}

void resetShutdown() {
  std::unique_lock<std::mutex> lock(kShutdownData.request_mutex);
  kShutdownData.requested = false;
}

void waitForShutdown() {
  std::unique_lock<std::mutex> lock(kShutdownData.request_mutex);
  kShutdownData.request_signal.wait(
      lock, [] { return (kShutdownData.requested) ? true : false; });
}

bool waitTimeoutOrShutdown(std::chrono::milliseconds timeout) {
  std::unique_lock<std::mutex> lock(kShutdownData.request_mutex);
  return kShutdownData.request_signal.wait_for(
      lock, timeout, [] { return kShutdownData.requested.load(); });
}

void requestShutdown(int retcode) {
  // Can be called from any thread, attempt a graceful shutdown.
  std::unique_lock<std::mutex> lock(kShutdownData.request_mutex);

  if (!kShutdownData.requested) {
    setShutdownExitCode(retcode);
    kShutdownData.requested = true;
    kShutdownData.request_signal.notify_all();
  }
}

void requestShutdown(int retcode, const std::string& message) {
  LOG(ERROR) << message;
  systemLog(message);
  requestShutdown(retcode);
}
} // namespace osquery
