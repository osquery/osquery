/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "tls.h"

#include <chrono>
#include <osquery/core/core.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/utils/config/default_paths.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/info/version.h>

#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

namespace osquery {

const std::string kTLSUserAgentBase = "osquery/";

/// TLS server hostname.
CLI_FLAG(string,
         tls_hostname,
         "",
         "TLS/HTTPS hostname for Config, Logger, and Enroll plugins");

/// Optional HTTP proxy server hostname.
CLI_FLAG(string, proxy_hostname, "", "Optional HTTP proxy hostname");

/// Path to optional TLS server/CA certificate(s), used for pinning.
CLI_FLAG(string,
         tls_server_certs,
         OSQUERY_CERTS_HOME "certs.pem",
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

/// Reuse TLS session sockets.
CLI_FLAG(bool, tls_session_reuse, true, "Reuse TLS session sockets");

/// Tear down TLS sessions after a custom timeout.
CLI_FLAG(uint32,
         tls_session_timeout,
         3600,
         "TLS session keep alive timeout in seconds");

#ifndef NDEBUG
HIDDEN_FLAG(bool,
            tls_allow_unsafe,
            false,
            "Allow TLS server certificate trust failures");
#endif

HIDDEN_FLAG(bool,
            tls_dump,
            false,
            "Print remote requests and responses to stderr");

/// Undocumented feature to override TLS endpoints.
HIDDEN_FLAG(bool, tls_node_api, false, "Use node key as TLS endpoints");

DECLARE_bool(verbose);

TLSTransport::TLSTransport() {
  if (FLAGS_tls_server_certs.size() > 0) {
    server_certificate_file_ = FLAGS_tls_server_certs;
  }

  if (FLAGS_tls_client_cert.size() > 0 && FLAGS_tls_client_key.size() > 0) {
    client_certificate_file_ = FLAGS_tls_client_cert;
    client_private_key_file_ = FLAGS_tls_client_key;
  }
}

void TLSTransport::decorateRequest(http::Request& r) {
  r << http::Request::Header("Content-Type", serializer_->getContentType());
  r << http::Request::Header("Accept", serializer_->getContentType());
  r << http::Request::Header("User-Agent", kTLSUserAgentBase + kVersion);
}

http::Client::Options TLSTransport::getOptions() {
  http::Client::Options options;

  options.follow_redirects(true).always_verify_peer(verify_peer_).timeout(16);

  if (server_certificate_file_.size() > 0) {
    if (!osquery::isReadable(server_certificate_file_).ok()) {
      LOG(WARNING) << "Cannot read TLS server certificate(s): "
                   << server_certificate_file_;
    } else {
      // There is a non-default server certificate set.
      boost::system::error_code ec;

      auto status = fs::status(server_certificate_file_, ec);

#ifndef NDEBUG
      if (!FLAGS_tls_allow_unsafe) {
        // In unsafe mode we skip verification of the server's TLS details
        // to allow people to connect to devservers
#else
      if (true) {
#endif
        options.openssl_verify_path(server_certificate_file_);
      }

      // On Windows, we cannot set openssl_certificate to a directory
      if (isPlatform(PlatformType::TYPE_WINDOWS) &&
          status.type() != fs::regular_file) {
        LOG(WARNING) << "Cannot set a non-regular file as a certificate: "
                     << server_certificate_file_;
      } else {
#ifndef NDEBUG
        if (!FLAGS_tls_allow_unsafe) {
#else
        if (true) {
#endif
          options.openssl_certificate(server_certificate_file_);
        }
      }
    }
  }

#ifndef NDEBUG
  // Configuration may allow unsafe TLS testing if compiled as a debug target.
  if (FLAGS_tls_allow_unsafe) {
    options.always_verify_peer(false);
  }
#endif

  return options;
}

http::Client::Options TLSTransport::getInternalOptions() {
  auto options = getOptions();

  options.keep_alive(FLAGS_tls_session_reuse);

  if (FLAGS_proxy_hostname.size() > 0) {
    options.proxy_hostname(FLAGS_proxy_hostname);
  }

  options.openssl_ciphers(kTLSCiphers);
  options.openssl_options(SSL_OP_NO_SSLv3 | SSL_OP_NO_SSLv2 | SSL_OP_NO_TLSv1 |
                          SSL_OP_NO_TLSv1_1 | SSL_OP_ALL);

  if (client_certificate_file_.size() > 0) {
    if (!osquery::isReadable(client_certificate_file_).ok()) {
      LOG(WARNING) << "Cannot read TLS client certificate: "
                   << client_certificate_file_;
    } else if (!osquery::isReadable(client_private_key_file_).ok()) {
      LOG(WARNING) << "Cannot read TLS client private key: "
                   << client_private_key_file_;
    } else {
      options.openssl_certificate_file(client_certificate_file_);
      options.openssl_private_key_file(client_private_key_file_);
    }
  }

  return options;
}

inline bool tlsFailure(const std::string& what) {
  if (what.find("Error") == 0 || what.find("refused") != std::string::npos) {
    return false;
  }
  return true;
}

static auto getClient() {
  std::shared_ptr<http::Client> client = nullptr;
  if (FLAGS_tls_session_reuse) {
    thread_local std::shared_ptr<http::Client> tl_client;
    thread_local auto last_time_reseted = std::chrono::system_clock::now();
    client = tl_client;

    if (client.get() == nullptr) {
      tl_client = client = std::make_shared<http::Client>();
    }

    if (FLAGS_tls_session_timeout > 0 &&
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now() - last_time_reseted)
                .count() > FLAGS_tls_session_timeout) {
      tl_client.reset();
      last_time_reseted = std::chrono::system_clock::now();
    }
  } else {
    client = std::make_shared<http::Client>();
  }
  return client;
}

void printRawStderr(const std::string& s) {
  fprintf(stderr, "%s\n", s.c_str());
}

Status TLSTransport::sendRequest() {
  if (destination_.find("https://") == std::string::npos) {
    return Status::failure(
        "Cannot create TLS request for non-HTTPS protocol URI");
  }

  http::Request r(destination_);
  decorateRequest(r);

  VLOG(1) << "TLS/HTTPS GET request to URI: " << destination_;
  try {
    std::shared_ptr<http::Client> client = getClient();

    client->setOptions(getInternalOptions());
    response_ = client->get(r);

    const auto& response_body = response_.body();
    if (FLAGS_verbose && FLAGS_tls_dump) {
      // Not using VLOG to avoid logging whole body to logging destination.
      printRawStderr(response_body);
    }
    response_status_ =
        serializer_->deserialize(response_body, response_params_);
  } catch (const std::exception& e) {
    return Status::failure(std::string("Request error: ") + e.what());
  }
  return response_status_;
}

Status TLSTransport::sendRequest(const std::string& params, bool compress) {
  if (destination_.find("https://") == std::string::npos) {
    return Status::failure(
        "Cannot create TLS request for non-HTTPS protocol URI");
  }

  http::Request r(destination_);
  decorateRequest(r);
  if (compress) {
    // Later, when posting/putting, the data will be optionally compressed.
    r << http::Request::Header("Content-Encoding", "gzip");
  }

  // Allow request calls to override the default HTTP POST verb.
  HTTPVerb verb;
  auto it = options_.doc().FindMember("_verb");

  verb = (HTTPVerb)(it != options_.doc().MemberEnd() && it->value.IsInt()
                        ? it->value.GetInt()
                        : HTTP_POST);

  VLOG(1) << "TLS/HTTPS " << ((verb == HTTP_POST) ? "POST" : "PUT")
          << " request to URI: " << destination_;
  if (FLAGS_verbose && FLAGS_tls_dump) {
    // Not using VLOG to avoid logging whole body to logging destination.
    printRawStderr(params);
  }

  try {
    std::shared_ptr<http::Client> client = getClient();
    client->setOptions(getInternalOptions());

    if (verb == HTTP_POST) {
      response_ = client->post(r, (compress) ? compressString(params) : params);
    } else {
      response_ = client->put(r, (compress) ? compressString(params) : params);
    }

    const auto& response_body = response_.body();
    if (FLAGS_verbose && FLAGS_tls_dump) {
      // Not using VLOG to avoid logging whole body to logging destination.
      printRawStderr(response_body);
    }
    response_status_ =
        serializer_->deserialize(response_body, response_params_);
  } catch (const std::exception& e) {
    return Status::failure(std::string("Request error: ") + e.what());
  }
  return response_status_;
}
} // namespace osquery
