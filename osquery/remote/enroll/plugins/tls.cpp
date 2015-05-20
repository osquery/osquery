/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/enroll.h>
#include <osquery/filesystem.h>

#include "osquery/remote/requests.h"
#include "osquery/remote/transports/tls.h"
#include "osquery/remote/serializers/json.h"

#define ENROLL_TLS_MAX_ATTEMPTS 3

namespace osquery {

/// Enrollment TLS endpoint (path) using TLS hostname.
FLAG(string,
     enroll_tls_endpoint,
     "",
     "TLS/HTTPS endpoint for client enrollment");

/// Path to optional enrollment secret data, sent with enrollment requests.
FLAG(string,
     enroll_secret_path,
     "",
     "Path to an optional client enrollment-auth secret");

class TLSEnrollPlugin : public EnrollPlugin {
 private:
  /// Enroll called, return cached key or if no key cached, call requestKey.
  std::string enroll(bool force);

 private:
  /// Request an enrollment key response from the TLS endpoint.
  Status requestKey(const std::string& uri);

 private:
  /// The cached enrollment key.
  std::string node_secret_key_;
};

REGISTER(TLSEnrollPlugin, "enroll", "tls");

std::string TLSEnrollPlugin::enroll(bool force) {
  // If no node secret has been negotiated, try a TLS request.
  auto uri = "https://" + FLAGS_tls_hostname + FLAGS_enroll_tls_endpoint;
  if (node_secret_key_.size() == 0 || force) {
    VLOG(1) << "TLSEnrollPlugin requesting a node enroll key from: " << uri;
    for (size_t i = 1; i <= ENROLL_TLS_MAX_ATTEMPTS; i++) {
      auto status = requestKey(uri);
      if (status.ok() || i == ENROLL_TLS_MAX_ATTEMPTS) {
        break;
      }

      LOG(WARNING) << "Failed enrollment request to " << uri << " ("
                   << status.what() << ") retrying...";
      ::sleep(i * i);
    }
  }

  return node_secret_key_;
}

Status TLSEnrollPlugin::requestKey(const std::string& uri) {
  // Read the optional enrollment secret data (sent with an enrollment request).
  std::string enroll_secret;
  if (FLAGS_enroll_secret_path.size() > 0) {
    osquery::readFile(FLAGS_enroll_secret_path, enroll_secret);
  }

  boost::property_tree::ptree params;
  params.put<std::string>("enroll_secret", enroll_secret);

  auto request = Request<TLSTransport, JSONSerializer>(uri);
  auto status = request.call(params);
  if (!status.ok()) {
    return status;
  }

  // The call succeeded, store the node secret key (the enrollment response).
  boost::property_tree::ptree recv;
  status = request.getResponse(recv);
  if (!status.ok()) {
    return status;
  }

  if (recv.count("enroll_key") > 0) {
    // Set the enroll key, should be stored in the RocksDB cache.
    // TODO: Store this response key in RocksDB.
    node_secret_key_ = recv.get<std::string>("enroll_key", "");
    return Status(0, "OK");
  } else {
    return Status(1, "No enrollment key returned from TLS enroll plugin");
  }
}
}
