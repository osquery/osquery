/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

 #include <boost/property_tree/ptree.hpp>

#include <osquery/enroll.h>
#include <osquery/flags.h>
#include <osquery/registry.h>

#include "osquery/remote/serializers/json.h"
#include "osquery/remote/utility.h"

#include "osquery/config/parsers/decorators.h"
#include "osquery/core/json.h"
#include "osquery/logger/plugins/tls_logger.h"

namespace osquery {

constexpr size_t kTLSMaxLogLines = 1024;

FLAG(string, logger_tls_endpoint, "", "TLS/HTTPS endpoint for results logging");

FLAG(uint64,
     logger_tls_period,
     4,
     "Seconds between flushing logs over TLS/HTTPS");

FLAG(uint64,
     logger_tls_max,
     1 * 1024 * 1024,
     "Max size in bytes allowed per log line");

FLAG(bool, logger_tls_compress, false, "GZip compress TLS/HTTPS request body");

REGISTER(TLSLoggerPlugin, "logger", "tls");

TLSLogForwarder::TLSLogForwarder()
    : BufferedLogForwarder("TLSLogForwarder",
                           "tls",
                           std::chrono::seconds(FLAGS_logger_tls_period),
                           kTLSMaxLogLines) {
  uri_ = TLSRequestHelper::makeURI(FLAGS_logger_tls_endpoint);
}

Status TLSLoggerPlugin::logString(const std::string& s) {
  return forwarder_->logString(s);
}

Status TLSLoggerPlugin::logStatus(const std::vector<StatusLogLine>& log) {
  return forwarder_->logStatus(log);
}

Status TLSLoggerPlugin::setUp() {
  auto node_key = getNodeKey("tls");
  if (!FLAGS_disable_enrollment && node_key.size() == 0) {
    // Could not generate a node key, continue logging to stderr.
    return Status(1, "No node key, TLS logging disabled.");
  }

  // Start the log forwarding/flushing thread.
  forwarder_ = std::make_shared<TLSLogForwarder>();
  Status s = forwarder_->setUp();
  if (!s.ok()) {
    LOG(ERROR) << "Error initializing TLS logger: " << s.getMessage();
    return s;
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
  JSON params;
  params.add("node_key", getNodeKey("tls"));
  params.add("log_type", log_type);

  {
    // Read each logged line into JSON and populate a list of lines.
    // The result list will use the 'data' key.
    auto children = params.newArray();
    iterate(log_data, ([&params, &children](std::string& item) {
              // Enforce a max log line size for TLS logging.
              if (item.size() > FLAGS_logger_tls_max) {
                LOG(WARNING) << "Line exceeds TLS logger max: " << item.size();
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
}
