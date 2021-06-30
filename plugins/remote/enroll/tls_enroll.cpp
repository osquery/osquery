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
#include <osquery/remote/transports/tls.h>
// clang-format on

#include "tls_enroll.h"

#include <osquery/remote/enroll/enroll.h>
#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>
#include <osquery/core/system.h>

#include <osquery/process/process.h>
#include <osquery/remote/requests.h>
#include <osquery/remote/serializers/json.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/core/shutdown.h>

namespace osquery {

DECLARE_string(enroll_secret_path);
DECLARE_bool(disable_enrollment);

CLI_FLAG(uint64,
         tls_enroll_max_attempts,
         12,
         "The total number of attempts that will be made to the enroll "
         "endpoint if a request fails, 0 for infinite");

CLI_FLAG(uint64,
         tls_enroll_max_interval,
         600,
         "Maximum wait time in seconds between enroll retry attempts");

/// Enrollment TLS endpoint (path) using TLS hostname.
CLI_FLAG(string,
         enroll_tls_endpoint,
         "",
         "TLS/HTTPS endpoint for client enrollment");

/// Undocumented feature for TLS access token passing.
HIDDEN_FLAG(bool,
            tls_secret_always,
            false,
            "Include TLS enroll secret in every request");

/// Undocumented feature to override TLS enrollment key name.
HIDDEN_FLAG(string,
            tls_enroll_override,
            "enroll_secret",
            "Override the TLS enroll secret key name");

REGISTER_INTERNAL(TLSEnrollPlugin, "enroll", "tls");

std::string TLSEnrollPlugin::enroll() {
  if (shutdownRequested()) {
    LOG(WARNING) << "Enrollment won't be attempted due to a shutdown request";
    return {};
  }

  // If no node secret has been negotiated, try a TLS request.
  auto uri = "https://" + FLAGS_tls_hostname + FLAGS_enroll_tls_endpoint;
  if (FLAGS_tls_secret_always) {
    uri += ((uri.find('?') != std::string::npos) ? '&' : '?') +
           FLAGS_tls_enroll_override + "=" + getEnrollSecret();
  }

  std::string node_key;
  VLOG(1) << "TLSEnrollPlugin requesting a node enroll key from: " << uri;

  std::uint64_t attempt = 1;
  std::uint64_t interval_step = 1;
  std::uint64_t interval = 0;

  bool should_shutdown = false;

  while (FLAGS_tls_enroll_max_attempts == 0 ||
         attempt <= FLAGS_tls_enroll_max_attempts) {
    auto status = requestKey(uri, node_key);
    if (status.ok() || attempt == FLAGS_tls_enroll_max_attempts) {
      break;
    }

    // Increase attempts only if we haven't chosen infinite retries
    if (FLAGS_tls_enroll_max_attempts > 0) {
      ++attempt;
    }

    LOG(WARNING) << "Failed enrollment request to " << uri << " ("
                 << status.what() << ") retrying...";

    interval =
        std::min(interval_step * interval_step, FLAGS_tls_enroll_max_interval);

    if (interval < FLAGS_tls_enroll_max_interval) {
      ++interval_step;
    }

    should_shutdown =
        waitTimeoutOrShutdown(std::chrono::milliseconds(interval * 1000));

    if (should_shutdown) {
      LOG(WARNING)
          << "Enrollment attempts interrupted due to a shutdown request";
      break;
    }
  }

  return node_key;
}

Status TLSEnrollPlugin::requestKey(const std::string& uri,
                                   std::string& node_key) {
  // Read the optional enrollment secret data (sent with an enrollment request).
  JSON params;
  params.add(FLAGS_tls_enroll_override, getEnrollSecret());
  params.add("host_identifier", getHostIdentifier());
  params.add("platform_type",
             std::to_string(static_cast<uint64_t>(kPlatformType)));

  // Select from each table describing host details.
  JSON host_details;
  genHostDetails(host_details);
  params.add("host_details", host_details.doc());

  Request<TLSTransport, JSONSerializer> request(uri);
  request.setOption("hostname", FLAGS_tls_hostname);
  auto status = request.call(params);
  if (!status.ok()) {
    return status;
  }

  // The call succeeded, store the node secret key (the enrollment response).
  JSON recv;
  status = request.getResponse(recv);
  if (!status.ok()) {
    return status;
  }

  // Support multiple response keys as a node key (identifier).
  auto it = recv.doc().FindMember("node_key");
  if (it == recv.doc().MemberEnd()) {
    it = recv.doc().FindMember("id");
  }

  if (it != recv.doc().MemberEnd()) {
    node_key = it->value.IsString() ? it->value.GetString() : "";
  }

  if (node_key.empty()) {
    return Status(1, "No node key returned from TLS enroll plugin");
  }
  return Status::success();
}
} // namespace osquery
