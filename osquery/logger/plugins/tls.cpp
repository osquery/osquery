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
#include <osquery/registry.h>

#include "osquery/remote/requests.h"
#include "osquery/remote/transports/tls.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/utility.h"
#include "osquery/database/db_handle.h"

#include "osquery/logger/plugins/tls.h"

namespace pt = boost::property_tree;

namespace osquery {

constexpr size_t kTLSMaxLogLines = 1024;
constexpr size_t kTLSMaxLogLineSize = 1 * 1024 * 1024;

FLAG(string, logger_tls_endpoint, "", "TLS/HTTPS endpoint for results logging");

FLAG(int32,
     logger_tls_period,
     4,
     "Seconds between flushing logs over TLS/HTTPS");

DECLARE_bool(tls_secret_always);
DECLARE_string(tls_enroll_override);
DECLARE_bool(tls_node_api);

REGISTER(TLSLoggerPlugin, "logger", "tls");

static inline std::string genLogIndex(bool results, unsigned long& counter) {
  return ((results) ? "r" : "s") + std::to_string(getUnixTime()) + "_" +
         std::to_string(++counter);
}

static inline void iterate(std::vector<std::string>& input,
                           std::function<void(std::string&)> predicate) {
  // Since there are no 'multi-do' APIs, keep a count of consecutive actions.
  // This count allows us to sleep the thread to prevent utilization thrash.
  size_t count = 0;
  for (auto& item : input) {
    // The predicate is provided a mutable string.
    // It may choose to clear/move the data.
    predicate(item);
    if (++count % 100 == 0) {
      osquery::interruptableSleep(20);
    }
  }
}

TLSLogForwarderRunner::TLSLogForwarderRunner(const std::string& node_key)
    : node_key_(node_key) {
  uri_ = TLSRequestHelper::makeURI(FLAGS_logger_tls_endpoint);
}

Status TLSLoggerPlugin::logString(const std::string& s) {
  auto index = genLogIndex(true, log_index_);
  return setDatabaseValue(kLogs, index, s);
}

Status TLSLoggerPlugin::logStatus(const std::vector<StatusLogLine>& log) {
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

  {
    // Read each logged line into JSON and populate a list of lines.
    // The result list will use the 'data' key.
    pt::ptree children;
    iterate(log_data,
            ([&children](std::string& item) {
              pt::ptree child;
              try {
                std::stringstream input;
                input << item;
                std::string().swap(item);
                pt::read_json(input, child);
              } catch (const pt::json_parser::json_parser_error& e) {
                // The log line entered was not valid JSON, skip it.
              }
              children.push_back(std::make_pair("", std::move(child)));
            }));
    params.add_child("data", std::move(children));
  }

  auto request = Request<TLSTransport, JSONSerializer>(uri_);
  return request.call(params);
}

void TLSLogForwarderRunner::check() {
  // Instead of using the 'help' database API, prefer to interact with the
  // DBHandle directly for additional performance.
  auto handle = DBHandle::getInstance();

  // Get a list of all the buffered log items, with a max of 1024 lines.
  std::vector<std::string> indexes;
  auto status = handle->Scan(kLogs, indexes, kTLSMaxLogLines);

  // For each index, accumulate the log line into the result or status set.
  std::vector<std::string> results, statuses;
  iterate(indexes,
          ([&handle, &results, &statuses](std::string& index) {
            std::string value;
            auto& target = ((index.at(0) == 'r') ? results : statuses);
            if (handle->Get(kLogs, index, value)) {
              // Enforce a max log line size for TLS logging.
              if (value.size() > kTLSMaxLogLineSize) {
                LOG(WARNING) << "Line exceeds TLS logger max: " << value.size();
              } else {
                target.push_back(std::move(value));
              }
            }
          }));

  // If any results/statuses were found in the flushed buffer, send.
  if (results.size() > 0) {
    if (!send(results, "result")) {
      VLOG(1) << "Could not send results to logger URI: " << uri_;
    } else {
      // Clear the results logs once they were sent.
      iterate(indexes,
              ([&results](std::string& index) {
                if (index.at(0) != 'r') {
                  return;
                }
                deleteDatabaseValue(kLogs, index);
              }));
    }
  }

  if (statuses.size() > 0) {
    if (!send(statuses, "status")) {
      VLOG(1) << "Could not send status logs to logger URI: " << uri_;
    } else {
      // Clear the status logs once they were sent.
      iterate(indexes,
              ([&results](std::string& index) {
                if (index.at(0) != 's') {
                  return;
                }
                deleteDatabaseValue(kLogs, index);
              }));
    }
  }
}

void TLSLogForwarderRunner::start() {
  while (true) {
    check();

    // Cool off and time wait the configured period.
    osquery::interruptableSleep(FLAGS_logger_tls_period * 1000);
  }
}
}
