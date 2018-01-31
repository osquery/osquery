/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <osquery/dispatcher.h>
#include <osquery/logger.h>

#include "osquery/logger/plugins/buffered.h"

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
