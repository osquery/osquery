/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <vector>
#include <string>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/enroll.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/database.h>

#include "osquery/dispatcher/dispatcher.h"
#include "osquery/remote/requests.h"
#include "osquery/remote/transports/tls.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/utility.h"

namespace pt = boost::property_tree;

namespace osquery {

FLAG(string, logger_tls_endpoint, "", "TLS/HTTPS endpoint for results logging");

FLAG(int32,
     logger_tls_period,
     4,
     "Seconds between flushing logs over TLS/HTTPS");

DECLARE_bool(tls_secret_always);
DECLARE_string(tls_enroll_override);
DECLARE_bool(tls_node_api);

/**
 * @brief Control the number of backing-store buffered logs.
 *
 * The TLSLogForwarderRunner run loop requests the set of log indexes before
 * sending logs to a TLS handler. If the number of indexes exceeds
 * kTLSLoggerBufferMax the thread will set TLSLoggerPlugin::stop_buffering.
 * Then the logger plugin stops buffering, and new logs will drop.
 */
const size_t kTLSLoggerBufferMax = 1024 * 1024;

class TLSLogForwarderRunner;

class TLSLoggerPlugin : public LoggerPlugin {
 public:
  TLSLoggerPlugin() : log_index_(0) {}

  /**
   * @brief The osquery logger initialization method.
   *
   * LoggerPlugin::init is optionally used by logger plugins to receive a
   * buffer of status logs generated between application start and logger
   * initialization. TLSLoggerPlugin will further buffer these logs into the
   * backing store. They will flush to a TLS endpoint under normal conditions
   * in a supporting/asynchronous thread.
   */
  Status init(const std::string& name, const std::vector<StatusLogLine>& log);

 public:
  /// Log a result string. This is the basic catch-all for snapshots and events.
  Status logString(const std::string& s);

  /// Log a status (ERROR/WARNING/INFO) message.
  Status logStatus(const std::vector<StatusLogLine>& log);

 private:
  /**
   * @brief Hold an auto-incrementing offset for buffered logs.
   *
   * Logs are buffered to a backing store until they can be flushed to a TLS
   * endpoint (based on latency/retry/etc options). Buffering uses a UNIX time
   * second precision for indexing and ordering. log_index_ helps prevent
   * collisions by appending an auto-increment counter.
   */
  unsigned long log_index_;

  /**
   * @brief Start dropping logs by preventing buffering.
   *
   * If the TLS endpoint goes down while running and the backing store of log
   * buffers fills up (exceeds a maximum number of log lines) then logs will
   * start dropping.
   */
  static bool stop_buffering;

 private:
  /// Allow the TLSLogForwardRunner thread to disable log buffering.
  friend class TLSLogForwarderRunner;
};

/// Initialize the buffering stop to false.
bool TLSLoggerPlugin::stop_buffering = false;

/**
 * @brief A log forwarder thread flushing database-buffered logs.
 *
 * The TLSLogForwarderRunner flushes buffered result and status logs based
 * on CLI/options settings. If an enrollment key is set (and checked) during
 * startup, this Dispatcher service is started.
 */
class TLSLogForwarderRunner : public InternalRunnable {
 public:
  explicit TLSLogForwarderRunner(const std::string& node_key)
      : node_key_(node_key) {
    uri_ = TLSRequestHelper::makeURI(FLAGS_logger_tls_endpoint);
  }

  /// A simple wait lock, and flush based on settings.
  void start();

 protected:
  /**
   * @brief Send labeled result logs.
   *
   * The log_data provided to send must be mutable.
   * To optimize for smaller memory, this will be moved into place within the
   * constructed property tree before sending.
   */
  Status send(std::vector<std::string>& log_data, const std::string& log_type);

  /// Receive an enrollment/node key from the backing store cache.
  std::string node_key_;

  /// Endpoint URI
  std::string uri_;
};

REGISTER(TLSLoggerPlugin, "logger", "tls");

static inline std::string genLogIndex(bool results, unsigned long& counter) {
  return ((results) ? "r" : "s") + std::to_string(getUnixTime()) + "_" +
         std::to_string(++counter);
}

Status TLSLoggerPlugin::logString(const std::string& s) {
  if (stop_buffering) {
    return Status(1, "Buffer is paused, dropping logs");
  }

  auto index = genLogIndex(true, log_index_);
  return setDatabaseValue(kLogs, index, s);
}

Status TLSLoggerPlugin::logStatus(const std::vector<StatusLogLine>& log) {
  if (stop_buffering) {
    return Status(1, "Buffer is paused, dropping logs");
  }

  for (const auto& item : log) {
    // Convert the StatusLogLine into ptree format, to convert to JSON.
    pt::ptree buffer;
    buffer.put("severity", (google::LogSeverity)item.severity);
    buffer.put("filename", item.filename);
    buffer.put("line", item.line);
    buffer.put("message", item.message);

    // Convert to JSON, for storing a string-representation in the database.
    std::string json;
    try {
      std::stringstream json_output;
      pt::write_json(json_output, buffer, false);
      json = json_output.str();
    } catch (const pt::json_parser::json_parser_error& e) {
      // The log could not be represented as JSON.
      return Status(1, e.what());
    }

    // Store the status line in a backing store.
    if (!json.empty()) {
      json.pop_back();
    }
    auto index = genLogIndex(false, log_index_);
    auto status = setDatabaseValue(kLogs, index, json);
    if (!status.ok()) {
      // Do not continue if any line fails.
      return status;
    }
  }

  return Status(0, "OK");
}

Status TLSLoggerPlugin::init(const std::string& name,
                             const std::vector<StatusLogLine>& log) {
  auto node_key = getNodeKey("tls");
  if (node_key.size() == 0) {
    // Could not generate an enrollment key, continue logging to stderr.
    FLAGS_logtostderr = true;
  } else {
    // Start the log forwarding/flushing thread.
    Dispatcher::addService(std::make_shared<TLSLogForwarderRunner>(node_key));
  }

  // Restart the glog facilities using the name init was provided.
  google::ShutdownGoogleLogging();
  google::InitGoogleLogging(name.c_str());
  return logStatus(log);
}

Status TLSLogForwarderRunner::send(std::vector<std::string>& log_data,
                                   const std::string& log_type) {
  pt::ptree params;
  params.put<std::string>("node_key", node_key_);
  params.put<std::string>("log_type", log_type);

  // Read each logged line into JSON and populate a list of lines.
  // The result list will use the 'data' key.
  pt::ptree children;
  for (auto& item : log_data) {
    pt::ptree child;
    try {
      std::stringstream input;
      input << item;
      pt::read_json(input, child);
    } catch (const pt::json_parser::json_parser_error& e) {
      // The log line entered was not valid JSON, skip it.
    }
    children.push_back(std::make_pair("", std::move(child)));
  }

  params.add_child("data", std::move(children));
  auto request = Request<TLSTransport, JSONSerializer>(uri_);
  return request.call(params);
}

inline void clearLogs(bool results, const std::vector<std::string>& indexes) {
  for (const auto& index : indexes) {
    if (results && index.at(0) != 'r') {
      continue;
    }
    // If the value was flushed, remove from the backing store.
    deleteDatabaseValue(kLogs, index);
  }
}

void TLSLogForwarderRunner::start() {
  while (true) {
    // Get a list of all the buffered log items.
    std::vector<std::string> indexes;
    auto status = scanDatabaseKeys(kLogs, indexes);
    if (indexes.size() > kTLSLoggerBufferMax) {
      // The log buffer is filled. Stop buffering and start dropping logs.
      TLSLoggerPlugin::stop_buffering = true;
    } else if (TLSLoggerPlugin::stop_buffering == true) {
      // If the buffering was paused, resume.
      TLSLoggerPlugin::stop_buffering = false;
    }

    std::vector<std::string> results, statuses;
    for (const auto& index : indexes) {
      std::string value;
      auto& target = ((index.at(0) == 'r') ? results : statuses);
      if (getDatabaseValue(kLogs, index, value)) {
        // Resist failure, only append delimiters if the value get succeeded.
        target.push_back(std::move(value));
      }
    }

    // If any results/statuses were found in the flushed buffer, send.
    if (results.size() > 0) {
      if (!send(results, "result")) {
        VLOG(1) << "Could not send results to logger URI: " << uri_;
      } else {
        // Clear the results logs once they were sent.
        clearLogs(true, indexes);
      }
    }
    if (statuses.size() > 0) {
      if (!send(statuses, "status")) {
        VLOG(1) << "Could not send status logs to logger URI: " << uri_;
      } else {
        // Clear the status logs once they were sent.
        clearLogs(false, indexes);
      }
    }

    // Cool off and time wait the configured period.
    osquery::interruptableSleep(FLAGS_logger_tls_period * 1000);
  }
}
}
