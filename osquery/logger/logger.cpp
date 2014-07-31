// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/logger.h"
#include "osquery/logger/plugin.h"

#include <algorithm>
#include <thread>

#include <gflags/gflags.h>
#include <glog/logging.h>

using osquery::core::Status;

namespace osquery { namespace logger {

const std::string kDefaultLogReceiverName = "filesystem";

DEFINE_string(
  log_receiver,
  kDefaultLogReceiverName,
  "The upstream log receiver to log messages to."
);

Status logString(const std::string& s) {
  return logString(s, FLAGS_log_receiver);
}

Status logString(const std::string& s, const std::string& receiver) {
  if (REGISTERED_LOGGER_PLUGINS.find(receiver) ==
      REGISTERED_LOGGER_PLUGINS.end()) {
    LOG(ERROR) << "Logger receiver " << receiver << " not found";
    return Status(1, "Logger receiver not found");
  }
  auto log_status =
    REGISTERED_LOGGER_PLUGINS.at(receiver)->logString(s);
  if (!log_status.ok()) {
    return log_status;
  }
  return Status(0, "OK");
}

Status logScheduledQueryLogItem(
  const osquery::db::ScheduledQueryLogItem& results) {
  return logScheduledQueryLogItem(results, FLAGS_log_receiver);
}

Status logScheduledQueryLogItem(
  const osquery::db::ScheduledQueryLogItem& results,
  const std::string& receiver) {
  std::string json;
  auto s = osquery::db::serializeScheduledQueryLogItemJSON(results, json);
  if (!s.ok()) {
    return s;
  }
  return logString(json, receiver);
}

}}
