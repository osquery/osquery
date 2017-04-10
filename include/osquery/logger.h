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

#include <string>
#include <vector>

#ifdef WIN32
#define GLOG_NO_ABBREVIATED_SEVERITIES
#define GOOGLE_GLOG_DLL_DECL
#endif

#include <glog/logging.h>

#include <boost/noncopyable.hpp>

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
  /// The host identifier
  std::string identifier;
  /// The ASCII time stamp for when the status message was emitted
  std::string calendar_time;
  /// The UNIX time for when the status message was emitted
  size_t time;
};

/**
 * @brief Logger plugin feature bits for complicated loggers.
 *
 * Logger plugins may opt-in to additional features like explicitly handling
 * Glog status events or requesting event subscribers to forward each event
 * directly to the logger. This enumeration tracks, and corresponds to, each
 * of the feature methods defined in a logger plugin.
 *
 * A specific registry call action can be used to retrieve an overloaded Status
 * object containing all of the opt-in features.
 */
enum LoggerFeatures {
  LOGGER_FEATURE_BLANK = 0,
  LOGGER_FEATURE_LOGSTATUS = 1,
  LOGGER_FEATURE_LOGEVENT = 2,
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
  Status call(const PluginRequest& request, PluginResponse& response) override;

  /**
   * @brief A feature method to decide if Glog should stop handling statuses.
   *
   * Return true if this logger plugin's #logStatus method should handle Glog
   * statuses exclusively. If true then Glog will stop writing status lines
   * to the configured log path.
   *
   * @return false if this logger plugin should NOT handle Glog statuses.
   */
  virtual bool usesLogStatus() {
    return false;
  }

  /**
   * @brief A feature method to decide if events should be forwarded.
   *
   * See the optional logEvent method.
   *
   * @return false if this logger plugin should NOT handle events directly.
   */
  virtual bool usesLogEvent() {
    return false;
  }

  /**
   * @brief Set the process name.
   */
  void setProcessName(const std::string& name) {
    process_name_ = name;
  }

  /**
   * @brief Get the process name.
   */
  const std::string& name() const {
    return process_name_;
  }

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
   * @param binary_name The string name of the process (argv[0]).
   * @param log The set of status (INFO, WARNING, ERROR) logs generated before
   * the logger's `init` method was called.
   */
  virtual void init(const std::string& binary_name,
                    const std::vector<StatusLogLine>& log) = 0;

  /**
   * @brief See the usesLogStatus method, log a Glog status.
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
  virtual Status logSnapshot(const std::string& s) {
    return logString(s);
  }

  /**
   * @brief Optionally handle each published event via the logger.
   *
   * It is possible to skip the database representation of event subscribers
   * and instead forward each added event to the active logger plugin.
   */
  virtual Status logEvent(const std::string& s) {
    return Status(1, "Not enabled");
  }

 private:
  std::string process_name_;
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
 */
void initLogger(const std::string& name);

/**
 * @brief Log a string using the default logger receiver.
 *
 * Note that this method should only be used to log results. If you'd like to
 * log normal osquery operations, use Google Logging.
 *
 * @param message the string to log
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
 * @param item the unmangled results from the query planner.
 *
 * @return Status indicating the success or failure of the operation
 */
Status logSnapshotQuery(const QueryLogItem& item);

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
void relayStatusLogs(bool async = false);

/// Inspect the number of internal-buffered status log lines.
size_t queuedStatuses();

/// Inspect the number of active internal status log sender threads.
size_t queuedSenders();

/**
 * @brief Write a log line to the OS system log.
 *
 * There are occasional needs to log independently of the osquery logging
 * facilities. This allows a feature (not a table) to bypass all osquery
 * configuration and log to the OS system log.
 *
 * Linux/Darwin: this uses syslog's LOG_NOTICE.
 */
void systemLog(const std::string& line);
}
