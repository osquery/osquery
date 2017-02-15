/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

/*
 * Our third-party version of cpp-netlib uses OpenSSL APIs.
 * On OS X these symbols are marked deprecated and clang will warn against
 * us including them. We are squashing the noise for OS X's OpenSSL only.
 *
 * This is placed here because of ordering issues. ASIO requires WinSock.h
 * not to be already included.
 */

// clang-format off
#ifdef WIN32
#pragma warning(push, 3)

/*
 * Suppressing warning C4005:
 * 'ASIO_ERROR_CATEGORY_NOEXCEPT': macro redefinition
 */
#pragma warning(disable: 4005)

/*
 * Suppressing warning C4244:
 * 'argument': conversion from '__int64' to 'long', possible loss of data
 */
#pragma warning(disable: 4244)
#else
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wunused-local-typedef"
#pragma clang diagnostic ignored "-W#pragma-messages"
#endif

#include <boost/network/protocol/http/client.hpp>

#ifdef WIN32
#pragma warning(pop)

/// We need to reinclude this to re-enable boost's warning suppression
#include <boost/config/compiler/visualc.hpp>
#else
#pragma clang diagnostic pop
#endif
// clang-format on

#include <openssl/ssl.h>
#include <openssl/crypto.h>

#ifndef OPENSSL_NO_SSL2
#define OPENSSL_NO_SSL2 1
#endif

#ifndef OPENSSL_NO_SSL3
#define OPENSSL_NO_SSL3 1
#endif

#define OPENSSL_NO_MD5 1
#define OPENSSL_NO_DEPRECATED 1

/// Newer versions of LibreSSL will lack SSL methods.
extern "C" {
#if defined(NO_SSL_TXT_SSLV3)
SSL_METHOD* SSLv3_server_method(void);
SSL_METHOD* SSLv3_client_method(void);
SSL_METHOD* SSLv3_method(void);
#endif
void ERR_remove_state(unsigned long);
}

#include <osquery/flags.h>

#include "osquery/remote/requests.h"

namespace osquery {

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
  virtual ~TLSTransport() {}

 public:
  TLSTransport();

  boost::network::http::client getClient();

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
  bool verify_peer_;

 protected:
  /**
    * @brief Modify a request object with base modifications
    *
    * @param The request object, to be modified
    */
  void decorateRequest(boost::network::http::client::request& r);

 protected:
  /// Storage for the HTTP response object
  boost::network::http::client::response response_;

 private:
  FRIEND_TEST(TLSTransportsTests, test_call);
  FRIEND_TEST(TLSTransportsTests, test_call_with_params);
  FRIEND_TEST(TLSTransportsTests, test_call_verify_peer);
  FRIEND_TEST(TLSTransportsTests, test_call_server_cert_pinning);
  FRIEND_TEST(TLSTransportsTests, test_call_client_auth);
  FRIEND_TEST(TLSTransportsTests, test_call_http);

  friend class TestDistributedPlugin;
};
}
