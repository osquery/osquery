/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <algorithm>
#include <thread>

#include <boost/noncopyable.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/extensions.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"

namespace pt = boost::property_tree;

namespace osquery {

FLAG(bool, verbose, false, "Enable verbose informational messages");
FLAG_ALIAS(bool, verbose_debug, verbose);
FLAG_ALIAS(bool, debug, verbose);

/// Despite being a configurable option, this is only read/used at load.
FLAG(bool, disable_logging, false, "Disable ERROR/INFO logging");

FLAG(string, logger_plugin, "filesystem", "Logger plugin name");

FLAG(bool, log_result_events, true, "Log scheduled results as events");

/**
 * @brief A custom Glog log sink for forwarding or buffering status logs.
 *
 * This log sink has two modes, it can buffer Glog status logs until an osquery
 * logger is initialized or forward Glog status logs to an initialized and
 * appropriate logger. The appropriateness is determined by the logger when its
 * LoggerPlugin::init method is called. If the `init` method returns success
 * then a BufferedLogSink will start forwarding status logs to
 * LoggerPlugin::logStatus.
 *
 * This facility will start buffering when first used and stop buffering
 * (aka remove itself as a Glog sink) using the exposed APIs. It will live
 * throughout the life of the process for two reasons: (1) It makes sense when
 * the active logger plugin is handling Glog status logs and (2) it must remove
 * itself as a Glog target.
 */
class BufferedLogSink : public google::LogSink, private boost::noncopyable {
 public:
  /// We create this as a Singleton for proper disable/shutdown.
  static BufferedLogSink& instance() {
    static BufferedLogSink sink;
    return sink;
  }

  /// The Glog-API LogSink call-in method.
  void send(google::LogSeverity severity,
            const char* full_filename,
            const char* base_filename,
            int line,
            const struct ::tm* tm_time,
            const char* message,
            size_t message_len);

 public:
  /// Accessor/mutator to dump all of the buffered logs.
  static std::vector<StatusLogLine>& dump() { return instance().logs_; }

  /// Set the forwarding mode of the buffering sink.
  static void forward(bool forward = false) { instance().forward_ = forward; }

  /// Remove the buffered log sink from Glog.
  static void disable() {
    if (instance().enabled_) {
      instance().enabled_ = false;
      google::RemoveLogSink(&instance());
    }
  }

  /// Add the buffered log sink to Glog.
  static void enable() {
    if (!instance().enabled_) {
      instance().enabled_ = true;
      google::AddLogSink(&instance());
    }
  }

  /**
   * @brief Add a logger plugin that should receive status updates.
   *
   * Since the logger may support multiple active logger plugins the sink
   * will keep track of those plugins that returned success after ::init.
   * This list of plugins will received forwarded messages from the sink.
   *
   * This list is important because sending logs to plugins that also use
   * and active Glog Sink (supports multiple) will create a logging loop.
   */
  static void addPlugin(const std::string& name) {
    instance().sinks_.push_back(name);
  }

  /// Retrieve the list of enabled plugins that should have logs forwarded.
  static const std::vector<std::string>& enabledPlugins() {
    return instance().sinks_;
  }

 public:
  BufferedLogSink(BufferedLogSink const&) = delete;
  void operator=(BufferedLogSink const&) = delete;

 private:
  /// Create the log sink as buffering or forwarding.
  BufferedLogSink() : forward_(false), enabled_(false) {}

  /// Remove the log sink.
  ~BufferedLogSink() { disable(); }

 private:
  /// Intermediate log storage until an osquery logger is initialized.
  std::vector<StatusLogLine> logs_;

  /// Should the sending act in a forwarding mode.
  bool forward_{false};
  bool enabled_{false};

  /// Track multiple loggers that should receive sinks from the send forwarder.
  std::vector<std::string> sinks_;
};

/// Scoped helper to perform logging actions without races.
class LoggerDisabler {
 public:
  LoggerDisabler() : stderr_status_(FLAGS_logtostderr) {
    BufferedLogSink::disable();
    FLAGS_logtostderr = true;
  }

  ~LoggerDisabler() {
    BufferedLogSink::enable();
    FLAGS_logtostderr = stderr_status_;
  }

 private:
  bool stderr_status_;
};

static void serializeIntermediateLog(const std::vector<StatusLogLine>& log,
                                     PluginRequest& request) {
  pt::ptree tree;
  for (const auto& log_item : log) {
    pt::ptree child;
    child.put("s", log_item.severity);
    child.put("f", log_item.filename);
    child.put("i", log_item.line);
    child.put("m", log_item.message);
    tree.push_back(std::make_pair("", child));
  }

  // Save the log as a request JSON string.
  std::ostringstream output;
  pt::write_json(output, tree, false);
  request["log"] = output.str();
}

static void deserializeIntermediateLog(const PluginRequest& request,
                                       std::vector<StatusLogLine>& log) {
  if (request.count("log") == 0) {
    return;
  }

  // Read the plugin request string into a JSON tree and enumerate.
  pt::ptree tree;
  try {
    std::stringstream input;
    input << request.at("log");
    pt::read_json(input, tree);
  } catch (const pt::json_parser::json_parser_error& e) {
    return;
  }

  for (const auto& item : tree.get_child("")) {
    log.push_back({
        (StatusLogSeverity)item.second.get<int>("s", O_INFO),
        item.second.get<std::string>("f", "<unknown>"),
        item.second.get<int>("i", 0),
        item.second.get<std::string>("m", ""),
    });
  }
}

void setVerboseLevel() {
  if (Flag::getValue("verbose") == "true") {
    // Turn verbosity up to 1.
    // Do log DEBUG, INFO, WARNING, ERROR to their log files.
    // Do log the above and verbose=1 to stderr.
    FLAGS_minloglevel = 0; // INFO
    FLAGS_stderrthreshold = 0; // INFO
    FLAGS_v = 1;
  } else {
    // Do NOT log INFO, WARNING, ERROR to stderr.
    // Do log only WARNING, ERROR to log sinks.
    FLAGS_minloglevel = 1; // WARNING
    FLAGS_stderrthreshold = 1; // WARNING
  }

  if (FLAGS_disable_logging) {
    // Do log ERROR to stderr.
    // Do NOT log INFO, WARNING, ERROR to their log files.
    FLAGS_logtostderr = true;
    if (!FLAGS_verbose) {
      // verbose flag will still emit logs to stderr.
      FLAGS_minloglevel = 2; // ERROR
    }
  }
}

void initStatusLogger(const std::string& name) {
  FLAGS_alsologtostderr = false;
  FLAGS_colorlogtostderr = true;
  FLAGS_logbufsecs = 0; // flush the log buffer immediately
  FLAGS_stop_logging_if_full_disk = true;
  FLAGS_max_log_size = 10; // max size for individual log file is 10MB
  FLAGS_logtostderr = true;

  setVerboseLevel();
  // Start the logging, and announce the daemon is starting.
  google::InitGoogleLogging(name.c_str());

  // If logging is disabled then do not buffer intermediate logs.
  if (!FLAGS_disable_logging) {
    // Create an instance of the buffered log sink and do not forward logs yet.
    BufferedLogSink::enable();
  }
}

void initLogger(const std::string& name, bool forward_all) {
  // Check if logging is disabled, if so then no need to shuttle intermediates.
  if (FLAGS_disable_logging) {
    return;
  }

  // Stop the buffering sink and store the intermediate logs.
  BufferedLogSink::disable();
  auto intermediate_logs = std::move(BufferedLogSink::dump());
  // Start the custom status logging facilities, which may instruct Glog as is
  // the case with filesystem logging.
  PluginRequest request = {{"init", name}};
  serializeIntermediateLog(intermediate_logs, request);
  if (!request["log"].empty()) {
    request["log"].pop_back();
  }

  const auto& logger_plugin = Registry::getActive("logger");
  // Allow multiple loggers, make sure each is accessible.
  for (const auto& logger : osquery::split(logger_plugin, ",")) {
    if (!Registry::exists("logger", logger)) {
      continue;
    }

    auto status = Registry::call("logger", logger, request);
    if (status.ok() || forward_all) {
      // When LoggerPlugin::init returns success we enable the log sink in
      // forwarding mode. Then Glog status logs are forwarded to logStatus.
      BufferedLogSink::forward(true);
      BufferedLogSink::enable();
      // To support multiple plugins we only add the names of plugins that
      // return a success status after initialization.
      BufferedLogSink::addPlugin(logger);
    }
  }
}

void BufferedLogSink::send(google::LogSeverity severity,
                           const char* full_filename,
                           const char* base_filename,
                           int line,
                           const struct ::tm* tm_time,
                           const char* message,
                           size_t message_len) {
  // Either forward the log to an enabled logger or buffer until one exists.
  if (forward_) {
    const auto& logger_plugin = Registry::getActive("logger");
    for (const auto& logger : osquery::split(logger_plugin, ",")) {
      auto& enabled = BufferedLogSink::enabledPlugins();
      if (std::find(enabled.begin(), enabled.end(), logger) != enabled.end()) {
        // May use the logs_ storage to buffer/delay sending logs.
        std::vector<StatusLogLine> log;
        log.push_back({(StatusLogSeverity)severity,
                       std::string(base_filename),
                       line,
                       std::string(message, message_len)});
        PluginRequest request = {{"status", "true"}};
        serializeIntermediateLog(log, request);
        if (!request["log"].empty()) {
          request["log"].pop_back();
        }
        Registry::call("logger", logger, request);
      }
    }
  } else {
    logs_.push_back({(StatusLogSeverity)severity,
                     std::string(base_filename),
                     line,
                     std::string(message, message_len)});
  }
}

Status LoggerPlugin::call(const PluginRequest& request,
                          PluginResponse& response) {
  QueryLogItem item;
  std::vector<StatusLogLine> intermediate_logs;
  if (request.count("string") > 0) {
    return this->logString(request.at("string"));
  } else if (request.count("snapshot") > 0) {
    return this->logSnapshot(request.at("snapshot"));
  } else if (request.count("health") > 0) {
    return this->logHealth(request.at("health"));
  } else if (request.count("init") > 0) {
    deserializeIntermediateLog(request, intermediate_logs);
    return this->init(request.at("init"), intermediate_logs);
  } else if (request.count("status") > 0) {
    deserializeIntermediateLog(request, intermediate_logs);
    return this->logStatus(intermediate_logs);
  } else {
    return Status(1, "Unsupported call to logger plugin");
  }
}

Status logString(const std::string& message, const std::string& category) {
  return logString(message, category, Registry::getActive("logger"));
}

Status logString(const std::string& message,
                 const std::string& category,
                 const std::string& receiver) {
  auto status = Registry::call(
      "logger", receiver, {{"string", message}, {"category", category}});
  return Status(0, "OK");
}

Status logQueryLogItem(const QueryLogItem& results) {
  return logQueryLogItem(results, Registry::getActive("logger"));
}

Status logQueryLogItem(const QueryLogItem& results,
                       const std::string& receiver) {
  std::vector<std::string> json_items;
  Status status;
  if (FLAGS_log_result_events) {
    status = serializeQueryLogItemAsEventsJSON(results, json_items);
  } else {
    std::string json;
    status = serializeQueryLogItemJSON(results, json);
    json_items.push_back(json);
  }
  if (!status.ok()) {
    return status;
  }

  for (auto& json : json_items) {
    if (!json.empty() && json.back() == '\n') {
      json.pop_back();
      status = logString(json, "event", receiver);
    }
  }
  return status;
}

Status logSnapshotQuery(const QueryLogItem& item) {
  std::string json;
  if (!serializeQueryLogItemJSON(item, json)) {
    return Status(1, "Could not serialize snapshot");
  }
  if (!json.empty() && json.back() == '\n') {
    json.pop_back();
  }
  return Registry::call("logger", {{"snapshot", json}});
}

Status logHealthStatus(const QueryLogItem& item) {
  std::string json;
  if (!serializeQueryLogItemJSON(item, json)) {
    return Status(1, "Could not serialize health");
  }
  if (!json.empty() && json.back() == '\n') {
    json.pop_back();
  }
  return Registry::call("logger", {{"health", json}});
}

void relayStatusLogs() {
  // Prevent our dumping and registry calling from producing additional logs.
  LoggerDisabler disabler;

  // Construct a status log plugin request.
  PluginRequest request = {{"status", "true"}};
  auto& status_logs = BufferedLogSink::dump();
  if (status_logs.size() == 0) {
    return;
  }
  serializeIntermediateLog(status_logs, request);
  if (!request["log"].empty()) {
    request["log"].pop_back();
  }

  // Skip the registry's logic, and send directly to the core's logger.
  PluginResponse response;
  if (!Registry::call("logger", request, response)) {
    // Flush the buffered status logs.
    // Otherwise the extension call failed and the buffering should continue.
    status_logs.clear();
  }
}
}
