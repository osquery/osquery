/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/remote/transports/tls.h"

#include <boost/asio/ssl/context_base.hpp>

#include <osquery/filesystem.h>

namespace http = boost::network::http;

/// Apple's 0.9.8 OpenSSL will lack TLS protocols.
extern "C" {
#if !defined(HAS_SSL_TXT_TLSV1_1) and !defined(HAS_SSL_TXT_TLSV1_2)
SSL_CTX* TLSv1_1_client_method(void) { return nullptr; }
SSL_CTX* TLSv1_1_method(void) { return nullptr; }
SSL_CTX* TLSv1_1_server_method(void) { return nullptr; }
#endif
#if !defined(HAS_SSL_TXT_TLSV1_2)
struct CRYPTO_THREADID;
void ERR_remove_thread_state(const CRYPTO_THREADID* tid) {}
SSL_CTX* TLSv1_2_client_method(void) { return nullptr; }
SSL_CTX* TLSv1_2_method(void) { return nullptr; }
SSL_CTX* TLSv1_2_server_method(void) { return nullptr; }
#endif
#if defined(NO_SSL_TXT_SSLV2)
SSL_METHOD* SSLv2_server_method(void) { return nullptr; }
SSL_METHOD* SSLv2_client_method(void) { return nullptr; }
SSL_METHOD* SSLv2_method(void) { return nullptr; }
#endif
#if defined(NO_SSL_TXT_SSLV3)
SSL_METHOD* SSLv3_server_method(void) { return nullptr; }
SSL_METHOD* SSLv3_client_method(void) { return nullptr; }
SSL_METHOD* SSLv3_method(void) { return nullptr; }
#endif
}

namespace osquery {

const std::string kTLSCiphers =
    "ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:"
    "DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:!MD5";
const std::string kTLSUserAgentBase = "osquery/";

/// TLS server hostname.
CLI_FLAG(string,
         tls_hostname,
         "",
         "TLS/HTTPS hostname for Config, Logger, and Enroll plugins");

/// Path to optional TLS server/CA certificate(s), used for pinning.
CLI_FLAG(string,
         tls_server_certs,
         "",
         "Optional path to a TLS server PEM certificate(s) bundle");

/// Path to optional TLS client certificate, used for enrollment/requests.
CLI_FLAG(string,
         tls_client_cert,
         "",
         "Optional path to a TLS client-auth PEM certificate");

/// Path to optional TLS client secret key, used for enrollment/requests.
CLI_FLAG(string,
         tls_client_key,
         "",
         "Optional path to a TLS client-auth PEM private key");

#if defined(DEBUG)
HIDDEN_FLAG(bool,
            tls_allow_unsafe,
            false,
            "Allow TLS server certificate trust failures");
#endif

/// Undocumented feature to override TLS endpoints.
HIDDEN_FLAG(bool, tls_node_api, false, "Use node key as TLS endpoints");

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
  r << boost::network::header("Accept", serializer_->getContentType());
  r << boost::network::header("Host", FLAGS_tls_hostname);
  r << boost::network::header("User-Agent", kTLSUserAgentBase + kVersion);
}

http::client TLSTransport::getClient() {
  http::client::options options;
  options.follow_redirects(true).always_verify_peer(verify_peer_).timeout(4);

  std::string ciphers = kTLSCiphers;
// Some Ubuntu 12.04 clients exhaust their cipher suites without SHA.
#if defined(HAS_SSL_TXT_TLSV1_2) && !defined(UBUNTU_PRECISE) && !defined(DARWIN)
  // Otherwise we prefer GCM and SHA256+
  ciphers += ":!CBC:!SHA";
#endif

#if defined(DEBUG)
  // Configuration may allow unsafe TLS testing if compiled as a debug target.
  if (FLAGS_tls_allow_unsafe) {
    options.always_verify_peer(false);
  }
#endif

  options.openssl_ciphers(ciphers);
  options.openssl_options(SSL_OP_NO_SSLv3 | SSL_OP_NO_SSLv2 | SSL_OP_ALL);

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

inline bool tlsFailure(const std::string& what) {
  if (what.find("Error") == 0 || what.find("refused") != std::string::npos) {
    return false;
  }
  return true;
}

Status TLSTransport::sendRequest() {
  if (destination_.find("https://") == std::string::npos) {
    return Status(1, "Cannot create TLS request for non-HTTPS protocol URI");
  }

  auto client = getClient();
  http::client::request r(destination_);
  decorateRequest(r);

  try {
    VLOG(1) << "TLS/HTTPS GET request to URI: " << destination_;
    response_ = client.get(r);
    response_status_ =
        serializer_->deserialize(body(response_), response_params_);
  } catch (const std::exception& e) {
    return Status((tlsFailure(e.what())) ? 2 : 1,
                  std::string("Request error: ") + e.what());
  }
  return response_status_;
}

Status TLSTransport::sendRequest(const std::string& params) {
  if (destination_.find("https://") == std::string::npos) {
    return Status(1, "Cannot create TLS request for non-HTTPS protocol URI");
  }

  auto client = getClient();
  http::client::request r(destination_);
  decorateRequest(r);

  // Allow request calls to override the default HTTP POST verb.
  HTTPVerb verb = HTTP_POST;
  if (options_.count("verb") > 0) {
    verb = (HTTPVerb)options_.get<int>("verb", HTTP_POST);
  }

  try {
    VLOG(1) << "TLS/HTTPS " << ((verb == HTTP_POST) ? "POST" : "PUT")
            << " request to URI: " << destination_;
    if (verb == HTTP_POST) {
      response_ = client.post(r, params);
    } else {
      response_ = client.put(r, params);
    }
    response_status_ =
        serializer_->deserialize(body(response_), response_params_);
  } catch (const std::exception& e) {
    return Status((tlsFailure(e.what())) ? 2 : 1,
                  std::string("Request error: ") + e.what());
  }
  return response_status_;
}
}
