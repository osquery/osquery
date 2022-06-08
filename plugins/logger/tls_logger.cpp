/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// clang-format off
// Keep it on top of all other includes to fix double include WinSock.h header file
// which is windows specific boost build problem
#include <osquery/remote/utility.h>
// clang-format on

#include "tls_logger.h"

#include <boost/property_tree/ptree.hpp>

#include <osquery/remote/enroll/enroll.h>
#include <osquery/core/flags.h>
#include <osquery/core/flagalias.h>
#include <osquery/registry/registry.h>

#include <osquery/remote/serializers/json.h>

#include <plugins/config/parsers/decorators.h>
#include <osquery/utils/json/json.h>

namespace osquery {

FLAG(uint64,
     logger_tls_max_lines,
     1024,
     "Max number of logs to send per period");

FLAG(string, logger_tls_endpoint, "", "TLS/HTTPS endpoint for results logging");

FLAG(uint64,
     logger_tls_period,
     4,
     "Seconds between flushing logs over TLS/HTTPS");

FLAG(uint64,
     logger_tls_max_linesize,
     1 * 1024 * 1024,
     "Max size in bytes allowed per log line");

FLAG(bool, tls_disable_status_log, false, "Disable sending status logs");

// The flag name logger_tls_max is deprecated.
FLAG_ALIAS(google::uint64, logger_tls_max, logger_tls_max_linesize);

FLAG(bool, logger_tls_compress, false, "GZip compress TLS/HTTPS request body");

REGISTER(TLSLoggerPlugin, "logger", "tls");

TLSLogForwarder::TLSLogForwarder()
    : BufferedLogForwarder("TLSLogForwarder",
                           "tls",
                           std::chrono::seconds(FLAGS_logger_tls_period),
                           FLAGS_logger_tls_max_lines) {
  uri_ = TLSRequestHelper::makeURI(FLAGS_logger_tls_endpoint);
}

Status TLSLoggerPlugin::logString(const std::string& s) {
  return forwarder_->logString(s);
}

Status TLSLoggerPlugin::logStatus(const std::vector<StatusLogLine>& log) {
  return forwarder_->logStatus(log);
}

Status TLSLoggerPlugin::setUp() {
  // Start the log forwarding/flushing thread.
  forwarder_ = std::make_shared<TLSLogForwarder>();
  Status s = forwarder_->setUp();
  if (!s.ok()) {
    LOG(ERROR) << "Error initializing TLS logger: " << s.getMessage();
    return s;
  }

  auto node_key = getNodeKey("tls");
  if (!FLAGS_disable_enrollment && node_key.size() == 0) {
    // Could not generate a node key, continue logging to stderr.
    return Status(1, "No node key, TLS logging disabled.");
  }

  Dispatcher::addService(forwarder_);

  return Status(0);
}

void TLSLoggerPlugin::init(const std::string& name,
                           const std::vector<StatusLogLine>& log) {
  logStatus(log);
}

Status TLSLogForwarder::send(std::vector<std::string>& log_data,
                             const std::string& log_type) {
  // Skip sending status logs to remote server if disabled
  if (FLAGS_tls_disable_status_log && log_type == "status") {
    return Status::success();
  }

  JSON params;
  params.add("node_key", getNodeKey("tls"));
  params.add("log_type", log_type);

  {
    // Read each logged line into JSON and populate a list of lines.
    // The result list will use the 'data' key.
    auto children = params.newArray();
    iterate(log_data, ([&params, &children](std::string& item) {
              // Enforce a max log line size for TLS logging.
              if (item.size() > FLAGS_logger_tls_max_linesize) {
                LOG(WARNING)
                    << "Linesize exceeds TLS logger maximum: " << item.size();
                return;
              }

              JSON child;
              Status s = child.fromString(item);
              if (!s.ok()) {
                // The log line entered was not valid JSON, skip it.
                return;
              }
              std::string().swap(item);
              params.push(child.doc(), children.doc());
            }));
    params.add("data", children.doc());
  }

  // The response body is ignored (status is set appropriately by
  // TLSRequestHelper::go())
  std::string response;
  if (FLAGS_logger_tls_compress) {
    params.add("_compress", true);
  }
  return TLSRequestHelper::go<JSONSerializer>(uri_, params, response);
}
} // namespace osquery
