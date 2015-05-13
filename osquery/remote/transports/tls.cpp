/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/network/protocol/http/client.hpp>

#include <osquery/filesystem.h>

#include "osquery/remote/transports/tls.h"

namespace http = boost::network::http;

namespace osquery {

const std::string kTLSUserAgent = "osquery/" STR(OSQUERY_BUILD_VERSION);

/// Path to optional TLS client secret key, used for enrollment/requests.
FLAG(string,
     tls_client_key,
     "",
     "Optional path to a client-auth TLS PEM private key");

/// Path to optional TLS client certificate, used for enrollment/requests.
FLAG(string,
     tls_client_cert,
     "",
     "Optional path to a client-auth TLS PEM certificate");

/// Path to optional TLS server/CA certificate(s), used for pinning.
FLAG(string,
     tls_server_certs,
     "",
     "Optional path to a TLS server PEM certificate(s) bundle");

/// TLS server hostname.
FLAG(string,
     tls_hostname,
     "",
     "TLS/HTTPS hostname for Config, Logger, and Enroll plugins");

TLSTransport::TLSTransport() : verify_peer_(true) {
  if (FLAGS_tls_server_certs.size() > 0) {
    server_certificate_file_ = FLAGS_tls_server_certs;
  }

  if (FLAGS_tls_client_cert.size() > 0 && FLAGS_tls_client_key.size() > 0) {
    client_certificate_file_ = FLAGS_tls_client_cert;
    client_private_key_file_ = FLAGS_tls_client_key;
  }
}

void TLSTransport::decorateRequest(http::client::request& r) {
  r << boost::network::header("Connection", "close");
  r << boost::network::header("Content-Type", serializer_->getContentType());
  r << boost::network::header("Accpet", serializer_->getContentType());
  r << boost::network::header("Host", FLAGS_tls_hostname);
  r << boost::network::header("User-Agent", kTLSUserAgent);
}

http::client TLSTransport::getClient() {
  http::client::options options;
  options.follow_redirects(true).always_verify_peer(verify_peer_).timeout(4);

  if (server_certificate_file_.size() > 0) {
    if (!osquery::isReadable(server_certificate_file_).ok()) {
      LOG(WARNING) << "Cannot read TLS server certificate(s): "
                   << server_certificate_file_;
    } else {
      // There is a non-default server certificate set.
      options.openssl_verify_path(server_certificate_file_);
      options.openssl_certificate(server_certificate_file_);
    }
  }

  if (client_certificate_file_.size() > 0) {
    if (!osquery::isReadable(client_certificate_file_).ok()) {
      LOG(WARNING)
          << "Cannot read TLS client certificate: " << client_certificate_file_;
    } else if (!osquery::isReadable(client_private_key_file_).ok()) {
      LOG(WARNING)
          << "Cannot read TLS client private key: " << client_private_key_file_;
    } else {
      options.openssl_certificate_file(client_certificate_file_);
      options.openssl_private_key_file(client_private_key_file_);
    }
  }

  http::client client(options);
  return client;
}

Status TLSTransport::sendRequest() {
  if (destination_.find("https://") == std::string::npos) {
    return Status(1, "Cannot create TLS request non https handler");
  }

  auto client = getClient();
  http::client::request r(destination_);
  decorateRequest(r);

  try {
    VLOG(1) << "TLS/HTTPS GET request to endpoint: " << destination_;
    response_ = client.get(r);
    response_status_ =
        serializer_->deserialize(body(response_), response_params_);
  } catch (const std::exception& e) {
    return Status(((std::string(e.what()).find("Error") == 0) ? 1 : 2),
                  std::string("Request error: ") + e.what());
  }
  return response_status_;
}

Status TLSTransport::sendRequest(const std::string& params) {
  if (destination_.find("https://") == std::string::npos) {
    return Status(1, "Cannot create TLS request non https handler");
  }

  auto client = getClient();
  http::client::request r(destination_);
  decorateRequest(r);

  try {
    VLOG(1) << "TLS/HTTPS POST request to endpoint: " << destination_;
    response_ = client.post(r, params);
    response_status_ =
        serializer_->deserialize(body(response_), response_params_);
  } catch (const std::exception& e) {
    return Status(((std::string(e.what()).find("Error") == 0) ? 1 : 2),
                  std::string("Request error: ") + e.what());
  }
  return response_status_;
}
}
