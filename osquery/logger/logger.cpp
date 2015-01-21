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

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/logger/plugin.h>

using osquery::Status;

namespace osquery {

/// `log_receiver` defines the default log receiver plugin name.
DEFINE_osquery_flag(string,
                    log_receiver,
                    "filesystem",
                    "The upstream log receiver to log messages to.");

DEFINE_osquery_flag(bool,
                    log_result_events,
                    true,
                    "Log scheduled results as events.");

Status logString(const std::string& s) {
  return logString(s, FLAGS_log_receiver);
}

Status logString(const std::string& s, const std::string& receiver) {
  if (REGISTERED_LOGGER_PLUGINS.find(receiver) ==
      REGISTERED_LOGGER_PLUGINS.end()) {
    LOG(ERROR) << "Logger receiver " << receiver << " not found";
    return Status(1, "Logger receiver not found");
  }
  auto log_status = REGISTERED_LOGGER_PLUGINS.at(receiver)->logString(s);
  if (!log_status.ok()) {
    return log_status;
  }
  return Status(0, "OK");
}

Status logScheduledQueryLogItem(const osquery::ScheduledQueryLogItem& results) {
  return logScheduledQueryLogItem(results, FLAGS_log_receiver);
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
