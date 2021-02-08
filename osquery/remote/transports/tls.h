/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <gtest/gtest_prod.h>

// clang-format off
// Keep it on top of all other includes to fix double include WinSock.h header file
// which is windows specific boost build problem
#include <osquery/remote/http_client.h>
// clang-format on

#include <osquery/core/flags.h>
#include <osquery/remote/requests.h>

namespace osquery {

const std::string kTLSCiphers =
    "ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:"
    "DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:!MD5:!CBC:!SHA";

/// Path to optional TLS client secret key, used for enrollment/requests.
DECLARE_string(tls_client_key);

/// Path to optional TLS client certificate (PEM), used for
/// enrollment/requests.
DECLARE_string(tls_client_cert);

/// TLS server hostname.
DECLARE_string(tls_hostname);

/**
 * @brief HTTP verb selections.
 */
enum HTTPVerb {
  HTTP_POST = 0,
  HTTP_PUT,
};

/**
 * @brief HTTPS (TLS) transport.
 */
class TLSTransport : public Transport {
 public:
  /**
   * @brief Send a simple request to the destination with no parameters
   *
   * @return A status indicating socket, network, or transport success/error.
   * Return code (1) for general connectivity problems, return code (2) for TLS
   * specific errors.
   */
  Status sendRequest() override;

  /**
   * @brief Send a simple request to the destination with parameters
   *
   * @param params A string representing the serialized parameters
   *
   * @return A status indicating socket, network, or transport success/error.
   * Return code (1) for general connectivity problems, return code (2) for TLS
   * specific errors.
   */
  Status sendRequest(const std::string& params, bool compress = false) override;

  /**
   * @brief Class destructor
   */
  virtual ~TLSTransport() = default;

 public:
  TLSTransport();

  /**
   * This returns the restrictive (best practice) set of options.
   * They include a limited cipher suite as well as the potential client
   * certificates.
   *
   * Use these options with a TLS client communicating with osquery-related
   * infrastructure.
   */
  http::Client::Options getInternalOptions();

  /**
   * This returns basic/generial options.
   *
   * Use these options if you are communicating with AWS or generic Internet
   * infrastructure.
   */
  http::Client::Options getOptions();

 private:
  /// Testing-only, disable peer verification.
  void disableVerifyPeer() {
    verify_peer_ = false;
  }

  /// Set TLS-client authentication options.
  void setClientCertificate(const std::string& certificate_file,
                            const std::string& private_key_file) {
    client_certificate_file_ = certificate_file;
    client_private_key_file_ = private_key_file;
  }

  /// Set TLS server/ca pinning options.
  void setPeerCertificate(const std::string& server_certificate_file) {
    server_certificate_file_ = server_certificate_file;
  }

 private:
  /// Optional TLS client-auth client certificate filename.
  std::string client_certificate_file_;

  /// Optional TLS client-auth client private key filename.
  std::string client_private_key_file_;

  /// Optional TLS server-pinning server certificate/bundle filename.
  std::string server_certificate_file_;

  /// Testing-only, disable peer verification.
  bool verify_peer_{true};

 protected:
  /**
   * @brief Modify a request object with base modifications
   *
   * @param The request object, to be modified
   */
  void decorateRequest(http::Request& r);

 protected:
  /// Storage for the HTTP response object
  http::Response response_;

 private:
  FRIEND_TEST(TLSTransportsTests, test_call);
  FRIEND_TEST(TLSTransportsTests, test_call_with_params);
  FRIEND_TEST(TLSTransportsTests, test_call_verify_peer);
  FRIEND_TEST(TLSTransportsTests, test_call_server_cert_pinning);
  FRIEND_TEST(TLSTransportsTests, test_call_client_auth);
  FRIEND_TEST(TLSTransportsTests, test_wrong_hostname);

  friend class TestDistributedPlugin;
};
} // namespace osquery
