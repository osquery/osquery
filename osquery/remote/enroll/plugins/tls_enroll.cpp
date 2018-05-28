/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/enroll.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/sql.h>
#include <osquery/system.h>

#include "osquery/remote/requests.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/transports/tls.h"
#include "osquery/core/process.h"

#include "osquery/remote/enroll/plugins/tls_enroll.h"

namespace osquery {

DECLARE_string(enroll_secret_path);
DECLARE_bool(disable_enrollment);
DECLARE_uint64(config_tls_max_attempts);

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

REGISTER(TLSEnrollPlugin, "enroll", "tls");

std::string TLSEnrollPlugin::enroll() {
  // If no node secret has been negotiated, try a TLS request.
  auto uri = "https://" + FLAGS_tls_hostname + FLAGS_enroll_tls_endpoint;
  if (FLAGS_tls_secret_always) {
    uri += ((uri.find('?') != std::string::npos) ? '&' : '?') +
           FLAGS_tls_enroll_override + "=" + getEnrollSecret();
  }

  std::string node_key;
  VLOG(1) << "TLSEnrollPlugin requesting a node enroll key from: " << uri;
  for (size_t i = 1; i <= FLAGS_config_tls_max_attempts; i++) {
    auto status = requestKey(uri, node_key);
    if (status.ok() || i == FLAGS_config_tls_max_attempts) {
      break;
    }

    LOG(WARNING) << "Failed enrollment request to " << uri << " ("
                 << status.what() << ") retrying...";
    sleepFor(i * i * 1000);
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
  return Status(0, "OK");
}
}
