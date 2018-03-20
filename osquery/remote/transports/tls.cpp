/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// clang-format off
// This must be here to prevent a WinSock.h exists error
#include "osquery/remote/transports/tls.h"
#include "osquery/dispatcher/io_service.h"
// clang-format on

#include <boost/filesystem.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>

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

#if defined(DEBUG)
HIDDEN_FLAG(bool,
            tls_allow_unsafe,
            false,
            "Allow TLS server certificate trust failures");
#endif

HIDDEN_FLAG(bool, tls_dump, false, "Print remote requests and responses");

/// Undocumented feature to override TLS endpoints.
HIDDEN_FLAG(bool, tls_node_api, false, "Use node key as TLS endpoints");

DECLARE_bool(verbose);

TLSTransport::TLSTransport() : verify_peer_(true) {
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

  options.keep_alive(FLAGS_tls_session_reuse);

  if (FLAGS_proxy_hostname.size() > 0) {
    options.proxy_hostname(FLAGS_proxy_hostname);
  }

#if defined(DEBUG)
  // Configuration may allow unsafe TLS testing if compiled as a debug target.
  if (FLAGS_tls_allow_unsafe) {
    options.always_verify_peer(false);
  }
#endif

  options.openssl_ciphers(kTLSCiphers);
  options.openssl_options(SSL_OP_NO_SSLv3 | SSL_OP_NO_SSLv2 | SSL_OP_ALL);

  if (server_certificate_file_.size() > 0) {
    if (!osquery::isReadable(server_certificate_file_).ok()) {
      LOG(WARNING) << "Cannot read TLS server certificate(s): "
                   << server_certificate_file_;
    } else {
      // There is a non-default server certificate set.
      boost_system::error_code ec;

      auto status = fs::status(server_certificate_file_, ec);
      options.openssl_verify_path(server_certificate_file_);

      // On Windows, we cannot set openssl_certificate to a directory
      if (isPlatform(PlatformType::TYPE_WINDOWS) &&
          status.type() != fs::regular_file) {
        LOG(WARNING) << "Cannot set a non-regular file as a certificate: "
                     << server_certificate_file_;
      } else {
        options.openssl_certificate(server_certificate_file_);
      }
    }
  }

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

  // 'Optionally', though all TLS plugins should set a hostname, supply an SNI
  // hostname. This will reveal the requested domain.
  auto it = options_.doc().FindMember("hostname");
  if (it != options_.doc().MemberEnd() && it->value.IsString()) {
    options.openssl_sni_hostname(it->value.GetString());
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
    client = tl_client;

    if (client.get() == nullptr) {
      tl_client = client = std::make_shared<http::Client>();

      if (FLAGS_tls_session_timeout > 0) {
        thread_local boost::asio::deadline_timer tl_timer(IOService::get());

        tl_timer.expires_from_now(
            boost::posix_time::seconds(FLAGS_tls_session_timeout));
        auto this_client = &tl_client;
        tl_timer.async_wait([this_client](boost_system::error_code const&) {
          (*this_client).reset();
        });
      }
    }
  } else {
    client = std::make_shared<http::Client>();
  }
  return client;
}

Status TLSTransport::sendRequest() {
  if (destination_.find("https://") == std::string::npos) {
    return Status(1, "Cannot create TLS request for non-HTTPS protocol URI");
  }

  http::Request r(destination_);
  decorateRequest(r);

  VLOG(1) << "TLS/HTTPS GET request to URI: " << destination_;
  try {
    std::shared_ptr<http::Client> client = getClient();

    client->setOptions(getOptions());
    response_ = client->get(r);

    const auto& response_body = response_.body();
    if (FLAGS_verbose && FLAGS_tls_dump) {
      fprintf(stdout, "%s\n", response_body.c_str());
    }
    response_status_ =
        serializer_->deserialize(response_body, response_params_);
  } catch (const std::exception& e) {
    return Status((tlsFailure(e.what())) ? 2 : 1,
                  std::string("Request error: ") + e.what());
  }
  return response_status_;
}

Status TLSTransport::sendRequest(const std::string& params, bool compress) {
  if (destination_.find("https://") == std::string::npos) {
    return Status(1, "Cannot create TLS request for non-HTTPS protocol URI");
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
    fprintf(stdout, "%s\n", params.c_str());
  }

  try {
    std::shared_ptr<http::Client> client = getClient();
    client->setOptions(getOptions());

    if (verb == HTTP_POST) {
      response_ = client->post(r, (compress) ? compressString(params) : params);
    } else {
      response_ = client->put(r, (compress) ? compressString(params) : params);
    }

    const auto& response_body = response_.body();
    if (FLAGS_verbose && FLAGS_tls_dump) {
      fprintf(stdout, "%s\n", response_body.c_str());
    }
    response_status_ =
        serializer_->deserialize(response_body, response_params_);
  } catch (const std::exception& e) {
    return Status((tlsFailure(e.what())) ? 2 : 1,
                  std::string("Request error: ") + e.what());
  }
  return response_status_;
}
}
