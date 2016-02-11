/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <osquery/logger.h>

#include "osquery/dispatcher/dispatcher.h"

namespace osquery {

class TLSLogForwarderRunner;

/**
 * @brief A log forwarder thread flushing database-buffered logs.
 *
 * The TLSLogForwarderRunner flushes buffered result and status logs based
 * on CLI/options settings. If an enrollment key is set (and checked) during
 * startup, this Dispatcher service is started.
 */
class TLSLogForwarderRunner : public InternalRunnable {
 public:
  explicit TLSLogForwarderRunner(const std::string& node_key);

  /// A simple wait lock, and flush based on settings.
  void start() override;

 protected:
  /**
   * @brief Send labeled result logs.
   *
   * The log_data provided to send must be mutable.
   * To optimize for smaller memory, this will be moved into place within the
   * constructed property tree before sending.
   */
  Status send(std::vector<std::string>& log_data, const std::string& log_type);

  /**
   * @brief Check for new logs and send.
   *
   * Scan the logs domain for up to 1024 log lines.
   * Sort those lines into status and request types then forward (send) each
   * set. On success, clear the data and indexes.
   */
  void check();

  /// Receive an enrollment/node key from the backing store cache.
  std::string node_key_;

  /// Endpoint URI
  std::string uri_;

 private:
  friend class TLSLoggerTests;
};

class TLSLoggerPlugin : public LoggerPlugin {
 public:
  TLSLoggerPlugin() : log_index_(0) {}

  /**
   * @brief The osquery logger initialization method.
   *
   * LoggerPlugin::init is optionally used by logger plugins to receive a
   * buffer of status logs generated between application start and logger
   * initialization. TLSLoggerPlugin will further buffer these logs into the
   * backing store. They will flush to a TLS endpoint under normal conditions
   * in a supporting/asynchronous thread.
   */
  Status init(const std::string& name,
              const std::vector<StatusLogLine>& log) override;

 public:
  /// Log a result string. This is the basic catch-all for snapshots and events.
  Status logString(const std::string& s) override;

  /// Log a status (ERROR/WARNING/INFO) message.
  Status logStatus(const std::vector<StatusLogLine>& log) override;

 private:
  /**
   * @brief Hold an auto-incrementing offset for buffered logs.
   *
   * Logs are buffered to a backing store until they can be flushed to a TLS
   * endpoint (based on latency/retry/etc options). Buffering uses a UNIX time
   * second precision for indexing and ordering. log_index_ helps prevent
   * collisions by appending an auto-increment counter.
   */
  size_t log_index_;

 private:
  /// Allow the TLSLogForwardRunner thread to disable log buffering.
  friend class TLSLogForwarderRunner;
  friend class TLSLoggerTests;
};
}
