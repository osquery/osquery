/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <algorithm>
#include <thread>

#include <boost/property_tree/json_parser.hpp>

#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

namespace pt = boost::property_tree;

namespace osquery {

FLAG(bool, verbose, false, "Enable verbose informational messages");
FLAG_ALIAS(bool, verbose_debug, verbose);
FLAG_ALIAS(bool, debug, verbose);

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
class BufferedLogSink : google::LogSink {
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

 private:
  /// Create the log sink as buffering or forwarding.
  BufferedLogSink() : forward_(false), enabled_(false) {}

  /// Remove the log sink.
  ~BufferedLogSink() { disable(); }

  BufferedLogSink(BufferedLogSink const&);
  void operator=(BufferedLogSink const&);

 private:
  /// Intermediate log storage until an osquery logger is initialized.
  std::vector<StatusLogLine> logs_;
  bool forward_;
  bool enabled_;
};

void serializeIntermediateLog(const std::vector<StatusLogLine>& log,
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

void unserializeIntermediateLog(const PluginRequest& request,
                                std::vector<StatusLogLine>& log) {
  if (request.count("log") == 0) {
    return;
  }

  // Read the plugin request string into a JSON tree and enumerate.
  std::stringstream input;
  input << request.at("log");
  pt::ptree tree;
  pt::read_json(input, tree);

  for (const auto& item : tree.get_child("")) {
    log.push_back({
        (StatusLogSeverity)item.second.get<int>("s"),
        item.second.get<std::string>("f"),
        item.second.get<int>("i"),
        item.second.get<std::string>("m"),
    });
  }
}

void initStatusLogger(const std::string& name) {
  FLAGS_alsologtostderr = true;
  FLAGS_logbufsecs = 0; // flush the log buffer immediately
  FLAGS_stop_logging_if_full_disk = true;
  FLAGS_max_log_size = 10; // max size for individual log file is 10MB
  FLAGS_logtostderr = true;

  if (FLAGS_verbose) {
    // Turn verbosity up to 1.
    // Do log DEBUG, INFO, WARNING, ERROR to their log files.
    // Do log the above and verbose=1 to stderr.
    FLAGS_v = 1;
  } else {
    // Do NOT log INFO, WARNING, ERROR to stderr.
    // Do log only WARNING, ERROR to log sinks.
    FLAGS_minloglevel = 1; // WARNING
    FLAGS_stderrthreshold = 1;
  }

  if (FLAGS_disable_logging) {
    // Do log ERROR to stderr.
    // Do NOT log INFO, WARNING, ERROR to their log files.
    FLAGS_logtostderr = true;
    if (!FLAGS_verbose) {
      // verbose flag still will still emit logs to stderr.
      FLAGS_minloglevel = 2; // ERROR
    }
  }

  // Start the logging, and announce the daemon is starting.
  google::InitGoogleLogging(name.c_str());

  // If logging is disabled then do not buffer intermediate logs.
  if (!FLAGS_disable_logging) {
    // Create an instance of the buffered log sink and do not forward logs yet.
    BufferedLogSink::enable();
  }
}

void initLogger(const std::string& name, bool forward_all) {
  // Check if logging is disabled, if it is no need to shuttle intermediates.
  if (FLAGS_disable_logging) {
    return;
  }

  BufferedLogSink::disable();
  auto intermediate_logs = std::move(BufferedLogSink::dump());
  auto& logger_plugin = Registry::getActive("logger");
  if (!Registry::exists("logger", logger_plugin)) {
    return;
  }

  // Set up the active logger plugin.
  Registry::get("logger", logger_plugin)->setUp();
  // Start the custom status logging facilities, which may instruct glog as is
  // the case with filesystem logging.
  PluginRequest request = {{"init", name}};
  serializeIntermediateLog(intermediate_logs, request);
  auto status = Registry::call("logger", request);
  if (status.ok() || forward_all) {
    // When init returns success we reenabled the log sink in forwarding
    // mode. Now, Glog status logs are buffered and sent to logStatus.
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
    // May use the logs_ storage to buffer/delay sending logs.
    std::vector<StatusLogLine> log;
    log.push_back({(StatusLogSeverity)severity,
                   std::string(base_filename),
                   line,
                   std::string(message, message_len)});
    PluginRequest request = {{"status", "true"}};
    serializeIntermediateLog(log, request);
    Registry::call("logger", request);
  } else {
    logs_.push_back({(StatusLogSeverity)severity,
                     std::string(base_filename),
                     line,
                     std::string(message, message_len)});
  }
}

Status LoggerPlugin::call(const PluginRequest& request,
                          PluginResponse& response) {
  std::vector<StatusLogLine> intermediate_logs;
  if (request.count("string") > 0) {
    return this->logString(request.at("string"));
  } else if (request.count("init") > 0) {
    unserializeIntermediateLog(request, intermediate_logs);
    return this->init(request.at("init"), intermediate_logs);
  } else if (request.count("status") > 0) {
    unserializeIntermediateLog(request, intermediate_logs);
    return this->logStatus(intermediate_logs);
  } else {
    return Status(1, "Unsupported call to logger plugin");
  }
}

Status logString(const std::string& s) {
  return logString(s, Registry::getActive("logger"));
}

Status logString(const std::string& s, const std::string& receiver) {
  if (!Registry::exists("logger", receiver)) {
    LOG(ERROR) << "Logger receiver " << receiver << " not found";
    return Status(1, "Logger receiver not found");
  }

  auto status = Registry::call("logger", receiver, {{"string", s}});
  return Status(0, "OK");
}

Status logScheduledQueryLogItem(const osquery::ScheduledQueryLogItem& results) {
  return logScheduledQueryLogItem(results, Registry::getActive("logger"));
}

Status logScheduledQueryLogItem(const osquery::ScheduledQueryLogItem& results,
                                const std::string& receiver) {
  std::string json;
  Status status;
  if (FLAGS_log_result_events) {
    status = serializeScheduledQueryLogItemAsEventsJSON(results, json);
  } else {
    status = serializeScheduledQueryLogItemJSON(results, json);
  }
  if (!status.ok()) {
    return status;
  }
  return logString(json, receiver);
}
}
