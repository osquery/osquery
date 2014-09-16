// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <memory>

#include "osquery/registry.h"
#include "osquery/status.h"

namespace osquery {

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
class LoggerPlugin {
 public:
  /** @brief Virtual method which should implement custom logging.
   *
   *  LoggerPlugin::logString should be implemented by a subclass of
   *  LoggerPlugin which needs to log a string in a custom way.
   *
   *  @return an instance of osquery::Status which indicates the success or
   *  failure of the operation.
   */
  virtual osquery::Status logString(const std::string& s) = 0;

  /// Virtual destructor
  virtual ~LoggerPlugin() {}
};
}

DECLARE_REGISTRY(LoggerPlugins,
                 std::string,
                 std::shared_ptr<osquery::LoggerPlugin>)

#define REGISTERED_LOGGER_PLUGINS REGISTRY(LoggerPlugins)

#define REGISTER_LOGGER_PLUGIN(name, decorator) \
  REGISTER(LoggerPlugins, name, decorator)
