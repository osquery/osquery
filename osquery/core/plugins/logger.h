/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>

#include <osquery/core/plugins/plugin.h>
#include <osquery/utils/status/status.h>

namespace osquery {

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
  /// An integer severity level mimicking Glog's.
  StatusLogSeverity severity;

  /// The name of the file emitting the status log.
  std::string filename;

  /// The line of the file emitting the status log.
  uint64_t line;

  /// The string-formatted status message.
  std::string message;

  /// The ASCII time stamp for when the status message was emitted
  std::string calendar_time;

  /// The UNIX time for when the status message was emitted
  uint64_t time;

  /**
   * @brief The host identifier at the time when logs are flushed.
   *
   * There is occasionally a delay between logging a status and decorating
   * with the host identifier. In most cases the identifier is static so this
   * does not matter. In some cases the host identifier causes database lookups.
   */
  std::string identifier;
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
   * @brief See the usesLogStatus method, log a Glog status.
   *
   * @param log A vector of parsed Glog log lines.
   * @return Status non-op indicating success or failure.
   */
  virtual Status logStatus(const std::vector<StatusLogLine>& log) {
    (void)log;
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
  virtual Status logEvent(const std::string& /*s*/) {
    return Status(1, "Not enabled");
  }

 protected:
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

 private:
  std::string process_name_;
};

} // namespace osquery
