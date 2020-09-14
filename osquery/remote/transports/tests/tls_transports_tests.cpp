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
#include "osquery/remote/transports/tls.h"
// clang-format on

#include <thread>

#include <gtest/gtest.h>

#include <osquery/logger/logger.h>
#include <osquery/core/system.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/info/platform_type.h>

#include "osquery/remote/requests.h"
#include "osquery/remote/serializers/json.h"

#include "osquery/remote/tests/test_utils.h"
#include "osquery/config/tests/test_utils.h"
#include "osquery/tests/test_util.h"

namespace osquery {

DECLARE_string(tls_server_certs);

class TLSTransportsTests : public testing::Test {
 public:
  std::string getTLSError(const Status& status) {
    auto error = "Could not complete TLSRequest (" +
                 std::to_string(status.getCode()) + "): " + status.what();
    return error;
  }

  bool nameError(const Status& status) {
    std::string name_error =
        "Request error: The format of the specified network name is invalid.";
    if (status.getMessage() == name_error) {
      return true;
    }

    return false;
  }

  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
  }

  void startServer(const std::string& server_cert = {}) {
    certs_ = FLAGS_tls_server_certs;
    FLAGS_tls_server_certs = "";
    ASSERT_TRUE(TLSServerRunner::start(server_cert));
    port_ = TLSServerRunner::port();
  }

  void TearDown() override {
    TLSServerRunner::stop();
    FLAGS_tls_server_certs = certs_;
  }

 protected:
  std::string port_;
  std::string certs_;
};

TEST_F(TLSTransportsTests, test_call) {
  startServer();

  // Create a transport and use a testing-only 'disableVerifyPeer' call.
  // This allows our client to complete TLS without verifying the fake
  // commonName or fake CA used by the testing server.
  auto t = std::make_shared<TLSTransport>();
  t->disableVerifyPeer();

  // Create a request using a TLSTransport and JSONSerializer.
  auto url = "https://localhost:" + port_;
  Request<TLSTransport, JSONSerializer> r(url, t);

  // Use the 'call' method on the request without any input parameters.
  // This will use a GET for the URI given in the Request constructor.
  Status status;
  ASSERT_NO_THROW(status = r.call());
  ASSERT_TRUE(status.ok()) << getTLSError(status);

  JSON recv;
  status = r.getResponse(recv);
  EXPECT_TRUE(status.ok());
}

TEST_F(TLSTransportsTests, test_call_with_params) {
  startServer();

  // Again, use a fake server/CA/commonName certificate.
  auto t = std::make_shared<TLSTransport>();
  t->disableVerifyPeer();

  auto url = "https://localhost:" + port_;
  Request<TLSTransport, JSONSerializer> r(url, t);

  // This time we'll construct a request parameter.
  JSON params;
  params.add("foo", "bar");

  // The call with a set of a params will push this "JSONSerializer"-serialized
  // data into the body of the request and issue a POST to the URI.
  Status status;
  ASSERT_NO_THROW(status = r.call(params));
  ASSERT_TRUE(status.ok()) << getTLSError(status);

  JSON recv;
  status = r.getResponse(recv);
  ASSERT_TRUE(status.ok());

  std::string json_expected, json_received;
  params.toString(json_expected);
  recv.toString(json_received);
  EXPECT_EQ(params.doc(), recv.doc())
      << "Expected: " << json_expected << "\nReceived: " << json_received;
}

TEST_F(TLSTransportsTests, test_call_verify_peer) {
  startServer();

  // Create a default request without a transport that accepts invalid peers.
  auto url = "https://localhost:" + port_;
  Request<TLSTransport, JSONSerializer> r(url);

  // The status/call will fail TLS negotiation because our client is trying
  // to verify the fake server, CA, commonName.
  Status status;
  ASSERT_NO_THROW(status = r.call());
  ASSERT_FALSE(status.ok());

  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    if (!nameError(status)) {
      EXPECT_EQ(status.getMessage(),
                "Request error: certificate verify failed");
    }
  } else {
    EXPECT_EQ(status.getMessage(), "Request error: certificate verify failed");
  }
}

TEST_F(TLSTransportsTests, test_call_server_cert_pinning) {
  startServer();

  // Require verification but include the server's certificate that includes
  // an unknown signing CA and wrong commonName.
  auto t = std::make_shared<TLSTransport>();
  t->setPeerCertificate(
      (getTestConfigDirectory() / "test_server_ca.pem").string());

  auto url = "https://localhost:" + port_;
  Request<TLSTransport, JSONSerializer> r1(url, t);

  Status status;
  ASSERT_NO_THROW(status = r1.call());
  ASSERT_TRUE(status.ok()) << getTLSError(status);

  // Now try with a path that is not a filename.
  t = std::make_shared<TLSTransport>();
  t->setPeerCertificate(getTestConfigDirectory().string());
  Request<TLSTransport, JSONSerializer> r2(url, t);

  ASSERT_NO_THROW(status = r2.call());
  EXPECT_FALSE(status.ok());
}

TEST_F(TLSTransportsTests, test_call_client_auth) {
  startServer();

  auto t = std::make_shared<TLSTransport>();
  t->setPeerCertificate(
      (getTestConfigDirectory() / "test_server_ca.pem").string());
  t->setClientCertificate(
      (getTestConfigDirectory() / "test_client.pem").string(),
      (getTestConfigDirectory() / "test_client.key").string());

  auto url = "https://localhost:" + port_;
  Request<TLSTransport, JSONSerializer> r(url, t);

  Status status;
  ASSERT_NO_THROW(status = r.call());
  EXPECT_TRUE(status.ok()) << getTLSError(status);
}

TEST_F(TLSTransportsTests, test_wrong_hostname) {
  startServer(
      (getTestConfigDirectory() / "test_server_wrong_hostname.pem").string());

  auto t = std::make_shared<TLSTransport>();
  t->setPeerCertificate(
      (getTestConfigDirectory() / "test_server_ca.pem").string());
  t->setClientCertificate(
      (getTestConfigDirectory() / "test_client.pem").string(),
      (getTestConfigDirectory() / "test_client.key").string());

  auto url = "https://localhost:" + port_;
  Request<TLSTransport, JSONSerializer> r(url, t);

  Status status;
  ASSERT_NO_THROW(status = r.call());
  EXPECT_FALSE(status.ok());
}
} // namespace osquery
