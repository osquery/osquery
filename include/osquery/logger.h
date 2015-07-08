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

#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/registry.h>

namespace osquery {

DECLARE_bool(disable_logging);
DECLARE_string(logger_plugin);

/**
 * @brief An internal severity set mapping to Glog's LogSeverity levels.
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
 * @brief Helper logging macro for table-generated verbose log lines.
 *
 * Since logging in tables does not always mean a critical warning or error
 * but more likely a parsing or expected edge-case, we provide a TLOG.
 *
 * The tool user can set within config or via the CLI what level of logging
 * to tolerate. It's the table developer's job to assume consistency in logging.
 */
#define TLOG VLOG(1)

/**
 * @brief Prepend a reference number to the log line.
 *
 * A reference number is an external-search helper for somewhat confusing or
 * seeminly-critical log lines.
 */
#define RLOG(n) "[Ref #" #n "] "

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
   * registry items are constructed, extension routes broadcasted and extension
   * plugins discovered (as a logger may be an extension plugin) and the config
   * has been loaded (which may include additional CLI flag-options).
   *
   * All of these actions may have generated VERBOSE, INFO, WARNING, or ERROR
   * logs. The internal logging facility, Glog, collects these intermediate
   * status logs and a customized log sink buffers them until the active
   * osquery logger's `init` method is called.
   *
   * The return status of `init` is very important. If a success is returned
   * then the Glog log sink stays active and now forwards every status log
   * to the logger's `logStatus` method. If a failure is returned this means
   * the logger does not support status logging and Glog should continue
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
   * @brief If the active logger's `init` method returned success then Glog
   * log lines will be collected, and forwarded to `logStatus`.
   *
   * `logStatus` and `init` are tightly coupled. Glog log lines will ONLY be
   * forwarded to `logStatus` if the logger's `init` method returned success.
   *
   * @param log A vector of parsed Glog log lines.
   * @return Status non-op indicating success or failure.
   */
  virtual Status logStatus(const std::vector<StatusLogLine>& log) {
    return Status(1, "Not enabled");
  }

  /**
   * @brief Optionally handle snapshot query results separately from events.
   *
   * If a logger plugin wants to write snapshot query results (potentially
   * large amounts of data) to a specific sink it should implement logSnapshot.
   * Otherwise the serialized log item data will be forwarded to logString.
   *
   * @param s A special log item will complete results from a query.
   * @return log status
   */
  virtual Status logSnapshot(const std::string& s) { return logString(s); }

  /// An optional health logging facility.
  virtual Status logHealth(const std::string& s) {
    return Status(1, "Not used");
  }
};

/// Set the verbose mode, changes Glog's sinking logic and will affect plugins.
void setVerboseLevel();

/// Start status logging to a buffer until the logger plugin is online.
void initStatusLogger(const std::string& name);

/**
 * @brief Initialize the osquery Logger facility by dumping the buffered status
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
 * @param category a category/metadata key
 *
 * @return Status indicating the success or failure of the operation
 */
Status logString(const std::string& message, const std::string& category);

/**
 * @brief Log a string using a specific logger receiver.
 *
 * Note that this method should only be used to log results. If you'd like to
 * log normal osquery operations, use Google Logging.
 *
 * @param message the string to log
 * @param category a category/metadata key
 * @param receiver a string representing the log receiver to use
 *
 * @return Status indicating the success or failure of the operation
 */
Status logString(const std::string& message,
                 const std::string& category,
                 const std::string& receiver);

/**
 * @brief Log results of scheduled queries to the default receiver
 *
 * @param item a struct representing the results of a scheduled query
 *
 * @return Status indicating the success or failure of the operation
 */
Status logQueryLogItem(const QueryLogItem& item);

/**
 * @brief Log results of scheduled queries to a specified receiver
 *
 * @param item a struct representing the results of a scheduled query
 * @param receiver a string representing the log receiver to use
 *
 * @return Status indicating the success or failure of the operation
 */
Status logQueryLogItem(const QueryLogItem& item, const std::string& receiver);

/**
 * @brief Log raw results from a query (or a snapshot scheduled query).
 *
 * @param results the unmangled results from the query planner.
 *
 * @return Status indicating the success or failure of the operation
 */
Status logSnapshotQuery(const QueryLogItem& item);

/**
 * @brief Log the worker's health along with health of each query.
 *
 * @param results the query results from the osquery schedule appended with a
 * row of health from the worker.
 *
 * @return Status indicating the success or failure of the operation
 */
Status logHealthStatus(const QueryLogItem& item);

/**
 * @brief Sink a set of buffered status logs.
 *
 * When the osquery daemon uses a watcher/worker set, the watcher's status logs
 * are accumulated in a buffered log sink. Well-performing workers should have
 * the set of watcher status logs relayed and sent to the configured logger
 * plugin.
 *
 * Status logs from extensions will be forwarded to the extension manager (core)
 * normally, but the watcher does not receive or send registry requests.
 * Extensions, the registry, configuration, and optional config/logger plugins
 * are all protected as a monitored worker.
 */
void relayStatusLogs();

/**
 * @brief Logger plugin registry.
 *
 * This creates an osquery registry for "logger" which may implement
 * LoggerPlugin. Only strings are logged in practice, and LoggerPlugin provides
 * a helper member for transforming PluginRequest%s to strings.
 */
CREATE_REGISTRY(LoggerPlugin, "logger");
}
