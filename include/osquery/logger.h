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

#include <future>
#include <string>
#include <vector>

#include <glog/logging.h>

#include <osquery/registry.h>
#include <osquery/status.h>
#include <osquery/scheduler.h>

namespace osquery {

/**
 * @brief A string which represents the default logger receiver
 *
 * The logger plugin that you use to define your config receiver can be
 * defined via a command-line flag, however, if you don't define a logger
 * plugin to use via the command-line, then the logger receiver which is
 * represented by the string stored kDefaultLogReceiverName will be used.
 */
extern const std::string kDefaultLogReceiverName;

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
 * @brief Superclass for the pluggable config component.
 *
 * In order to make the logging of osquery results easy to integrate into your
 * environment, we take advantage of a plugin interface which allows you to
 * integrate osquery with your internal large-scale logging infrastructure.
 * You may use flume, splunk, syslog, scribe, etc. In order to use your
 * specific upstream logging systems, one simply needs to create a custom
 * subclass of LoggerPlugin. That subclass should implement the
 * LoggerPlugin::logString method.
 *
 * Consider the following example:
 *
 * @code{.cpp}
 *   class TestLoggerPlugin : public ConfigPlugin {
 *    public:
 *     virtual osquery::Status logString(const std::string& s) {
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
 *  REGISTER_LOGGER_PLUGIN(
 *      "test", std::make_shared<osquery::TestLoggerPlugin>());
 * @endcode
 */

class LoggerPlugin : public Plugin {
 public:
  /** @brief Virtual method which should implement custom logging.
   *
   *  LoggerPlugin::logString should be implemented by a subclass of
   *  LoggerPlugin which needs to log a string in a custom way.
   *
   *  @return an instance of osquery::Status which indicates the success or
   *  failure of the operation.
   */
  virtual Status logString(const std::string& s) = 0;
  Status call(const PluginRequest& request, PluginResponse& response);
};

namespace registry {
/**
 * @brief Logger plugin registry.
 *
 * This creates an osquery registry for "logger" which may implement
 * LoggerPlugin. Only strings are logged in practice, and LoggerPlugin provides
 * a helper member for transforming PluginRequest%s to strings.
 */
const auto LoggerRegistry = NewRegistry::create<LoggerPlugin>("logger");
}
}
