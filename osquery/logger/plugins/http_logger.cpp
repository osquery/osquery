/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/database.h>

#include "osquery/dispatcher/dispatcher.h"
#include "http_logger.h"

namespace pt = boost::property_tree;

namespace osquery {

class LogForwarder;

FLAG(string,
     logger_uri,
     "",
     "Endpoint path for ERROR/WARN/INFO and results logging");

FLAG(int32, max_data_size, 0, "The max size of the sent log blob");
FLAG(int32,
     log_force_send_time,
     0,
     "After this long, send logs even if it's not at the threshold");
FLAG(int32,
     log_force_send_threshold,
     0,
     "After this long, send logs even if it's not elapsed the time period");
FLAG(int32, log_check_interval, 0, "The time between log amount checks");

REGISTER(HTTPLoggerPlugin, "logger", "http");

Status HTTPLoggerPlugin::setUp() { return Status(0, "OK"); }

Status HTTPLoggerPlugin::logString(const std::string& s) {
  auto stat = DBHandle::getInstance()->Put(
      kLogs,
      std::to_string(osquery::getUnixTime()) + "_" + std::to_string(++log_num),
      s);
  return stat;
}

Status HTTPLoggerPlugin::logStatus(const std::vector<StatusLogLine>& log) {
  for (const auto& item : log) {
    boost::property_tree::ptree new_log;
    new_log.put("action", "status_log");
    new_log.put("severity", (google::LogSeverity)item.severity);
    new_log.put("content", item.filename + " " + std::to_string(item.line) +
                               " " + item.message);
    std::stringstream ss;
    write_json(ss, new_log);
    auto stat = DBHandle::getInstance()->Put(
        kLogs, std::to_string(osquery::getUnixTime()) + "_" +
                   std::to_string(++log_num),
        ss.str());
    if (!stat.ok()) {
      std::cout << stat.getMessage() << "\n";
      return stat;
    }
  }
  return Status(0, "OK");
}

Status HTTPLoggerPlugin::init(const std::string& name,
                              const std::vector<StatusLogLine>& log) {
  // Stop the internal glog facilities.
  google::ShutdownGoogleLogging();

  PluginResponse resp;
  Status s = Registry::call("enrollment", "get_key", {{"enroll", "0"}}, resp);
  // If the call was successful and returned an enrollment key
  if (!s.ok() || resp.size() == 0 || resp[0]["key"].length() == 0) {
    // We could not get an enrollment key, so we can send logs, best we can do
    // is log to stderr
    FLAGS_logtostderr = true;
  }
  // Restart the glog facilities using the name init was provided.
  google::InitGoogleLogging(name.c_str());
  Status stat = logStatus(log);
  if (!stat.ok()) {
    return stat;
  }
  return Status(0, "OK");
}

class LogForwarder : public InternalRunnable {
  LogForwarder() {}

  ~LogForwarder() {}

  /// Anything that needs to happen to verify that the LogForwarder can run
  Status initVerify() {
    if (FLAGS_max_data_size == 0) {
      return Status(1, "NOK");
    }
    if (FLAGS_log_force_send_time == 0) {
      return Status(1, "NOK");
    }
    if (FLAGS_log_check_interval == 0) {
      return Status(1, "NOK");
    }
    if (FLAGS_log_force_send_threshold == 0) {
      // set";
      return Status(1, "NOK");
    }
    if (!DBHandle::getInstance()->checkDB()) {
      // VLOG(1) << "Could not start log forwarding loop, database checkDB
      // failed";
      return Status(1, "NOK");
    }
    return Status(0, "OK");
  }

  void enter() {
    // Verify configuration is good
    if (!initVerify().ok()) {
      // We couldn't setup remote logging, so try to use filesystem
      return;
    }
    std::vector<std::string> logs;

    while (true) {
      for (int i = 0; i < FLAGS_log_force_send_time / FLAGS_log_check_interval;
           ++i) {
        auto stat = DBHandle::getInstance()->Scan(kLogs, logs);
        if (stat.ok()) {
          return;
        }
        if (logs.size() > FLAGS_log_force_send_threshold) {
          break;
        }
        logs.clear();
        osquery::interruptableSleep(FLAGS_log_check_interval);
      }

      std::vector<std::string> send_blobs;
      int bytes_of_data = FLAGS_max_data_size;
      // Split our vector of returned strings into requests that fit the
      // FLAGS_max_data_size
      int last_blob_end = -1;
      for (int i = 0; i < logs.size(); i++) {
        bytes_of_data -= logs[i].length();
        if (bytes_of_data < 0) {
          // There are now too many bytes of data
          if (FLAGS_max_data_size < logs[i].length()) {
            // This log is too big and cannot ever be sent, it must be dropped
            bytes_of_data += logs[i].length();
            logs.erase(logs.begin() + i);
          } else {
            std::string log_item;
            for (int j = last_blob_end + 1; j < i - 1; j++) {
              log_item += (logs[j] + ", ");
            }
            log_item += (logs[i]);
            last_blob_end = i;
            send_blobs.push_back(log_item);
          }
        }
      }
      // Logs should be split into chunks of size small enough to send
      for (const auto& item : send_blobs) {
      }
    }
  }
};
}
