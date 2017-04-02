/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#ifndef WIN32
#include <syslog.h>
#endif

#include <algorithm>
#include <thread>

#include <boost/noncopyable.hpp>

#include <osquery/events.h>
#include <osquery/extensions.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"
#include "osquery/core/json.h"

namespace pt = boost::property_tree;

namespace osquery {

FLAG(bool, verbose, false, "Enable verbose informational messages");
FLAG_ALIAS(bool, verbose_debug, verbose);
FLAG_ALIAS(bool, debug, verbose);

/// Despite being a configurable option, this is only read/used at load.
FLAG(bool, disable_logging, false, "Disable ERROR/INFO logging");

FLAG(string, logger_plugin, "filesystem", "Logger plugin name");

FLAG(bool, logger_event_type, true, "Log scheduled results as events");
FLAG_ALIAS(bool, log_result_events, logger_event_type);

/// Alias for the minloglevel used internally by GLOG.
FLAG(int32, logger_min_status, 0, "Minimum level for status log recording");

FLAG(bool,
     logger_secondary_status_only,
     false,
     "Only send status logs to secondary logger plugins");

/**
 * @brief Logger plugin registry.
 *
 * This creates an osquery registry for "logger" which may implement
 * LoggerPlugin. Only strings are logged in practice, and LoggerPlugin provides
 * a helper member for transforming PluginRequest%s to strings.
 */
CREATE_REGISTRY(LoggerPlugin, "logger");

class LoggerDisabler;

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
            size_t message_len) override;

 public:
  /// Accessor/mutator to dump all of the buffered logs.
  static std::vector<StatusLogLine>& dump() {
    return instance().logs_;
  }

  /// Set the forwarding mode of the buffering sink.
  static void forward(bool forward = false) {
    WriteLock lock(instance().forward_mutex_);
    instance().forward_ = forward;
  }

  /// Turn off forwarding and lock the instance forwarding state.
  /// Caller MUST make matching restoreForwardingAndUnlock call.
  static bool haltForwardingAndLock() {
    instance().forward_mutex_.lock();
    bool current_state = instance().forward_;
    instance().forward_ = false;
    return current_state;
  }

  /// Restore forwarding state and unlock.
  static void restoreForwardingAndUnlock(bool forward) {
    instance().forward_ = forward;
    instance().forward_mutex_.unlock();
  }

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

  /**
   * @brief Check if a given logger plugin was the first or 'primary'.
   *
   * Within the osquery core the BufferedLogSink acts as a router for status
   * logs. While initializing it inspects the set of logger plugins and saves
   * the first as the 'primary'.
   *
   * Checks within the core may act on this state. Checks within extensions
   * cannot, and thus any check for primary logger plugins is true.
   * While this is a limitation, in practice if a remote logger plugin is called
   * it is intended to receive all logging data.
   *
   * @param plugin Check if this target plugin is primary.
   * @return true of the provided plugin was the first specified.
   */
  static bool isPrimaryLogger(const std::string& plugin) {
    auto& self = instance();
    WriteLock lock(self.primary_mutex_);
    return (self.primary_.empty() || plugin == self.primary_);
  }

  /// Set the primary logger plugin is none has been previously specified.
  static void setPrimary(const std::string& plugin) {
    auto& self = instance();
    WriteLock lock(self.primary_mutex_);
    if (self.primary_.empty()) {
      self.primary_ = plugin;
    }
  }

 public:
  BufferedLogSink(BufferedLogSink const&) = delete;
  void operator=(BufferedLogSink const&) = delete;

 private:
  /// Create the log sink as buffering or forwarding.
  BufferedLogSink() : forward_(false), enabled_(false) {}

  /// Remove the log sink.
  ~BufferedLogSink() {
    disable();
  }

 private:
  /// Intermediate log storage until an osquery logger is initialized.
  std::vector<StatusLogLine> logs_;

  /// Should the sending act in a forwarding mode.
  bool forward_{false};

  /// Is the logger temporarily disabled.
  bool enabled_{false};

  /// Track multiple loggers that should receive sinks from the send forwarder.
  std::vector<std::string> sinks_;

  /// Keep track of the first, or 'primary' logger.
  std::string primary_;

  /// Mutex for checking primary status.
  Mutex primary_mutex_;

  /// Mutex to safely turn on/off forwarding
  Mutex forward_mutex_;

 private:
  friend class LoggerDisabler;
  friend class LoggerForwardingDisabler;
};

/// Scoped helper to perform logging actions without races.
class LoggerDisabler : private boost::noncopyable {
 public:
  LoggerDisabler()
      : stderr_status_(FLAGS_logtostderr),
        enabled_(BufferedLogSink::instance().enabled_) {
    BufferedLogSink::disable();
    FLAGS_logtostderr = true;
  }

  ~LoggerDisabler() {
    // Only enable if the sink was enabled when the disabler was requested.
    if (enabled_) {
      BufferedLogSink::enable();
    }
    FLAGS_logtostderr = stderr_status_;
  }

 private:
  /// Value of the 'logtostderr' Glog status when constructed.
  bool stderr_status_;

  /// Value of the BufferedLogSink's enabled status when constructed.
  bool enabled_;
};

/// Scoped helper to disable forwarding
LoggerForwardingDisabler::LoggerForwardingDisabler() {
  forward_state_ = BufferedLogSink::haltForwardingAndLock();
}

LoggerForwardingDisabler::~LoggerForwardingDisabler() {
  BufferedLogSink::restoreForwardingAndUnlock(forward_state_);
}

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
  } catch (const pt::json_parser::json_parser_error& /* e */) {
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
    FLAGS_minloglevel = google::GLOG_INFO;
    if (FLAGS_logger_plugin != "stdout") {
      // Special case for the stdout plugin.
      FLAGS_stderrthreshold = google::GLOG_INFO;
    }
    FLAGS_v = 1;
  } else {
    // Do NOT log INFO, WARNING, ERROR to stderr.
    // Do log only WARNING, ERROR to log sinks.
    auto default_level = google::GLOG_INFO;
    if (kToolType == ToolType::SHELL) {
      default_level = google::GLOG_WARNING;
    }

    if (Flag::isDefault("minloglevel")) {
      FLAGS_minloglevel = default_level;
    }

    if (Flag::isDefault("stderrthreshold")) {
      FLAGS_stderrthreshold = default_level;
    }
  }

  if (!Flag::isDefault("logger_min_status")) {
    long int i = 0;
    safeStrtol(Flag::getValue("logger_min_status"), 10, i);
    FLAGS_minloglevel = static_cast<decltype(FLAGS_minloglevel)>(i);
  }

  if (FLAGS_disable_logging) {
    // Do log ERROR to stderr.
    // Do NOT log INFO, WARNING, ERROR to their log files.
    FLAGS_logtostderr = true;
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

void initLogger(const std::string& name) {
  // Check if logging is disabled, if so then no need to shuttle intermediates.
  if (FLAGS_disable_logging) {
    return;
  }

  // Stop the buffering sink and store the intermediate logs.
  BufferedLogSink::disable();
  auto intermediate_logs = std::move(BufferedLogSink::dump());

  // Start the custom status logging facilities, which may instruct Glog as is
  // the case with filesystem logging.
  PluginRequest init_request = {{"init", name}};
  serializeIntermediateLog(intermediate_logs, init_request);
  if (!init_request["log"].empty()) {
    init_request["log"].pop_back();
  }

  bool forward = false;
  PluginRequest features_request = {{"action", "features"}};
  auto logger_plugin = RegistryFactory::get().getActive("logger");
  // Allow multiple loggers, make sure each is accessible.
  for (const auto& logger : osquery::split(logger_plugin, ",")) {
    BufferedLogSink::setPrimary(logger);
    if (!RegistryFactory::get().exists("logger", logger)) {
      continue;
    }

    Registry::call("logger", logger, init_request);
    auto status = Registry::call("logger", logger, features_request);
    if ((status.getCode() & LOGGER_FEATURE_LOGSTATUS) > 0) {
      // Glog status logs are forwarded to logStatus.
      forward = true;
      // To support multiple plugins we only add the names of plugins that
      // return a success status after initialization.
      BufferedLogSink::addPlugin(logger);
    }

    if ((status.getCode() & LOGGER_FEATURE_LOGEVENT) > 0) {
      EventFactory::addForwarder(logger);
    }
  }

  if (forward) {
    // Turn on buffered log forwarding only after all plugins have going through
    // their initialization.
    BufferedLogSink::forward(true);
    BufferedLogSink::enable();
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
    auto logger_plugin = RegistryFactory::get().getActive("logger");
    for (const auto& logger : osquery::split(logger_plugin, ",")) {
      auto& enabled = BufferedLogSink::enabledPlugins();
      if (std::find(enabled.begin(), enabled.end(), logger) != enabled.end()) {
        // May use the logs_ storage to buffer/delay sending logs.
        logs_.push_back({(StatusLogSeverity)severity,
                         std::string(base_filename),
                         line,
                         std::string(message, message_len)});
        PluginRequest request = {{"status", "true"}};
        serializeIntermediateLog(logs_, request);
        if (!request["log"].empty()) {
          request["log"].pop_back();
        }
        logs_.clear();
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
  if (FLAGS_logger_secondary_status_only &&
      !BufferedLogSink::isPrimaryLogger(getName()) &&
      (request.count("string") || request.count("snapshot"))) {
    return Status(0, "Logging disabled to secondary plugins");
  }

  QueryLogItem item;
  std::vector<StatusLogLine> intermediate_logs;
  if (request.count("string") > 0) {
    return this->logString(request.at("string"));
  } else if (request.count("snapshot") > 0) {
    return this->logSnapshot(request.at("snapshot"));
  } else if (request.count("init") > 0) {
    deserializeIntermediateLog(request, intermediate_logs);
    this->setProcessName(request.at("init"));
    this->init(this->name(), intermediate_logs);
    return Status(0);
  } else if (request.count("status") > 0) {
    deserializeIntermediateLog(request, intermediate_logs);
    return this->logStatus(intermediate_logs);
  } else if (request.count("event") > 0) {
    return this->logEvent(request.at("event"));
  } else if (request.count("action") && request.at("action") == "features") {
    size_t features = 0;
    features |= (usesLogStatus()) ? LOGGER_FEATURE_LOGSTATUS : 0;
    features |= (usesLogEvent()) ? LOGGER_FEATURE_LOGEVENT : 0;
    return Status(static_cast<int>(features));
  } else {
    return Status(1, "Unsupported call to logger plugin");
  }
}

Status logString(const std::string& message, const std::string& category) {
  return logString(
      message, category, RegistryFactory::get().getActive("logger"));
}

Status logString(const std::string& message,
                 const std::string& category,
                 const std::string& receiver) {
  if (FLAGS_disable_logging) {
    return Status(0, "Logging disabled");
  }

  return Registry::call(
      "logger", receiver, {{"string", message}, {"category", category}});
}

Status logQueryLogItem(const QueryLogItem& results) {
  return logQueryLogItem(results, RegistryFactory::get().getActive("logger"));
}

Status logQueryLogItem(const QueryLogItem& results,
                       const std::string& receiver) {
  if (FLAGS_disable_logging) {
    return Status(0, "Logging disabled");
  }

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
  if (FLAGS_disable_logging) {
    return Status(0, "Logging disabled");
  }

  std::string json;
  if (!serializeQueryLogItemJSON(item, json)) {
    return Status(1, "Could not serialize snapshot");
  }
  if (!json.empty() && json.back() == '\n') {
    json.pop_back();
  }
  return Registry::call("logger", {{"snapshot", json}});
}

bool haltForwardingAndLock() {
  return (BufferedLogSink::haltForwardingAndLock());
}

void restoreForwardingAndUnlock(bool forward) {
  BufferedLogSink::restoreForwardingAndUnlock(forward);
}

void relayStatusLogs() {
  if (FLAGS_disable_logging) {
    return;
  }

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
  Registry::call("logger", request, response);

  // Flush the buffered status logs.
  // If the logger called failed then the logger is experiencing a catastrophic
  // failure, since it is missing from the registry. The logger plugin may
  // return failure, but it should have buffered independently of the failure.
  status_logs.clear();
}

void systemLog(const std::string& line) {
#ifndef WIN32
  syslog(LOG_NOTICE, "%s", line.c_str());
#endif
}
}
