/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include "plugins/logger/buffered.h"

#include <osquery/core/plugins/logger.h>
#include <osquery/dispatcher/dispatcher.h>

namespace osquery {

/**
 * @brief A log forwarder thread flushing database-buffered logs.
 *
 * The TLSLogForwarder flushes buffered result and status logs based
 * on CLI/options settings. If an enrollment key is set (and checked) during
 * startup, this Dispatcher service is started.
 */
class TLSLogForwarder : public BufferedLogForwarder {
 public:
  explicit TLSLogForwarder();

 protected:
  Status send(std::vector<std::string>& log_data,
              const std::string& log_type) override;

  /// Endpoint URI
  std::string uri_;

 private:
  friend class TLSLoggerTests;
};

class TLSLoggerPlugin : public LoggerPlugin {
 public:
  /**
   * @brief The osquery logger initialization method.
   *
   * LoggerPlugin::init is optionally used by logger plugins to receive a
   * buffer of status logs generated between application start and logger
   * initialization. TLSLoggerPlugin will further buffer these logs into the
   * backing store. They will flush to a TLS endpoint under normal conditions
   * in a supporting/asynchronous thread.
   */
  void init(const std::string& name,
            const std::vector<StatusLogLine>& log) override;

  /// Setup node key and worker thread for sending logs.
  Status setUp() override;

  bool usesLogStatus() override {
    return true;
  }

 protected:
  /// Log a result string. This is the basic catch-all for snapshots and events.
  Status logString(const std::string& s) override;

  /// Log a status (ERROR/WARNING/INFO) message.
  Status logStatus(const std::vector<StatusLogLine>& log) override;

 private:
  /// Forwarder that buffers/sends logs. Runs in a Dispatcher thread.
  std::shared_ptr<TLSLogForwarder> forwarder_{nullptr};

 private:
  friend class TLSLoggerTests;
};
}
