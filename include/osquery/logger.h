/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <string>
#include <vector>

#include <glog/logging.h>

#include <osquery/registry.h>
#include <osquery/status.h>
#include <osquery/scheduler.h>

namespace osquery {

/**
 * @breif An internal severity set mapping to Glog's LogSeverity levels.
 */
enum StatusLogSeverity {
  O_INFO = 0,
  O_WARNING = 1,
  O_ERROR = 2,
  O_FATAL = 3,
};

/// An intermediate status log line.
struct StatusLogLine {
 public:
  /// An integer severity level mimicing Glog's.
  StatusLogSeverity severity;
  /// The name of the file emitting the status log.
  std::string filename;
  /// The line of the file emitting the status log.
  int line;
  /// The string-formatted status message.
  std::string message;
};

/**
 * @brief Superclass for the pluggable logging facilities.
 *
 * In order to make the logging of osquery results and inline debug, warning,
 * error status easy to integrate into your environment, we take advantage of
 * a plugin interface which allows you to integrate osquery with your internal
 * large-scale logging infrastructure.
 *
 * You may use flume, splunk, syslog, scribe, etc. In order to use your
 * specific upstream logging systems, one simply needs to create a custom
 * subclass of LoggerPlugin. That subclass should at least implement the
 * LoggerPlugin::logString method.
 *
 * Consider the following example:
 *
 * @code{.cpp}
 *   class TestLoggerPlugin : public LoggerPlugin {
 *    public:
 *     osquery::Status logString(const std::string& s) {
 *       int i = 0;
 *       internal::logStringToFlume(s, i);
 *       std::string message;
 *       if (i == 0) {
 *         message = "OK";
 *       } else {
 *         message = "Failed";
 *       }
 *       return osquery::Status(i, message);
 *     }
 *  };
 *
 *  REGISTER(TestLoggerPlugin, "logger", "test");
 * @endcode
 */
class LoggerPlugin : public Plugin {
 public:
  /// The LoggerPlugin PluginRequest action router.
  Status call(const PluginRequest& request, PluginResponse& response);

 protected:
  /** @brief Virtual method which should implement custom logging.
   *
   *  LoggerPlugin::logString should be implemented by a subclass of
   *  LoggerPlugin which needs to log a string in a custom way.
   *
   *  @return an instance of osquery::Status which indicates the success or
   *  failure of the operation.
   */
  virtual Status logString(const std::string& s) = 0;

  /**
   * @brief Initialize the logger with the name of the binary and any status
   * logs generated between program launch and logger start.
   *
   * The logger initialization is called once CLI flags have been parsed, the
   * registry items are constructed, extension routes broadcased and extension
   * plugins discovered (as a logger may be an extension plugin) and the config
   * has been loaded (which may include additional CLI flag-options).
   *
   * All of these actions may have generated VERBOSE, INFO, WARNING, or ERROR
   * logs. The internal logging facility is, glog, collects these intermediate
   * status logs and a customized log sink buffers them until the active
   * osquery logger's `init` method is called.
   *
   * The return status of `init` is very important. If a success is returned
   * then the glog log sink stays active and now forwards every status log
   * to the logger's `logStatus` method. If a failure is returned this means
   * the logger does not support status logging and glog should continue
   * as the only status log sink.
   *
   * @param binary_name The string name of the process (argv[0]).
   * @param log The set of status (INFO, WARNING, ERROR) logs generated before
   * the logger's `init` method was called.
   * @return Status success if the logger will continue to handle status logs
   * using `logStatus` or failure if status logging is not supported.
   */
  virtual Status init(const std::string& binary_name,
                      const std::vector<StatusLogLine>& log) {
    return Status(1, "Status logs are not supported by this logger");
  }

  /**
   * @brief If the active logger's `init` method returned success then glog
   * log lines will be collected, and forwarded to `logStatus`.
   *
   * `logStatus` and `init` are tightly coupled. Glog log lines will ONLY be
   * forwarded to `logStatus` if the logger's `init` method returned success.
   *
   * @param log A vector of parsed glog log lines.
   * @return Status non-op indicating success or failure.
   */
  virtual Status logStatus(const std::vector<StatusLogLine>& log) {
    return Status(1, "Not enabled");
  }
};

/// Start status logging to a buffer until the logger plugin is online.
void initStatusLogger(const std::string& name);

/**
 * @brief Initialize the osquery Logger facility by dump the buffered status
 * logs and configurating status log forwarding.
 *
 * initLogger will disable the `BufferedLogSink` facility, dump any status logs
 * emitted between process start and this init call, then configure the new
 * logger facility to receive status logs.
 *
 * The `forward_all` control is used when buffering logs in extensions.
 * It is fine if the logger facility in the core app does not want to receive
 * status logs, but this is NOT an option in extensions/modules. All status
 * logs must be forwarded to the core.
 *
 * @param name The process name.
 * @param forward_all Override the LoggerPlugin::init forwarding decision.
 */
void initLogger(const std::string& name, bool forward_all = false);

/**
 * @brief Log a string using the default logger receiver.
 *
 * Note that this method should only be used to log results. If you'd like to
 * log normal osquery operations, use Google Logging.
 *
 * @param s the string to log
 *
 * @return an instance of osquery::Status, indicating the success or failure
 * of the operation.
 */
Status logString(const std::string& s);

/**
 * @brief Log a string using a specific logger receiver.
 *
 * Note that this method should only be used to log results. If you'd like to
 * log normal osquery operations, use Google Logging.
 *
 * @param s the string to log
 * @param receiver a string representing the log receiver to use
 *
 * @return an instance of osquery::Status, indicating the success or failure
 * of the operation.
 */
Status logString(const std::string& s, const std::string& receiver);

/**
 * @brief Directly log results of scheduled queries to the default receiver
 *
 * @param item a struct representing the results of a scheduled query
 *
 * @return an instance of osquery::Status, indicating the success or failure
 * of the operation.
 */
Status logScheduledQueryLogItem(const ScheduledQueryLogItem& item);

/**
 * @brief Directly log results of scheduled queries to a specified receiver
 *
 * @param item a struct representing the results of a scheduled query
 * @param receiver a string representing the log receiver to use
 *
 * @return an instance of osquery::Status, indicating the success or failure
 * of the operation.
 */
Status logScheduledQueryLogItem(const ScheduledQueryLogItem& item,
                                const std::string& receiver);

/**
 * @brief Logger plugin registry.
 *
 * This creates an osquery registry for "logger" which may implement
 * LoggerPlugin. Only strings are logged in practice, and LoggerPlugin provides
 * a helper member for transforming PluginRequest%s to strings.
 */
CREATE_REGISTRY(LoggerPlugin, "logger");
}
