/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// clang-format off
// Keep it on top of all other includes to fix double include WinSock.h header file
// which is windows specific boost build problem
#include "osquery/remote/transports/tls.h"
// clang-format on

#include <thread>

#include <gtest/gtest.h>

#include <osquery/logger.h>
#include <osquery/system.h>
#include <osquery/registry_factory.h>

#include "osquery/remote/requests.h"
#include "osquery/remote/serializers/json.h"

#include "osquery/remote/tests/test_utils.h"
#include "osquery/config/tests/test_utils.h"
#include "osquery/tests/test_util.h"

namespace osquery {

DECLARE_bool(disable_database);
DECLARE_string(tls_server_certs);

class TLSTransportsTests : public testing::Test {
 public:
  bool verify(const Status& status) {
    if (!status.ok()) {
      LOG(ERROR) << "Could not complete TLSRequest (" << status.getCode()
                 << "): " << status.what();
    }

    // Sometimes the best we can test is the call workflow.
    if (status.getCode() == 1) {
      // The socket bind failed or encountered a connection error in the test.
      LOG(ERROR) << "Not failing TLS-based transport tests";
      return false;
    }

    return true;
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
    Initializer::platformSetup();
    registryAndPluginInit();
    FLAGS_disable_database = true;
    DatabasePlugin::setAllowOpen(true);
    DatabasePlugin::initPlugin();

    certs_ = FLAGS_tls_server_certs;
    FLAGS_tls_server_certs = "";
    TLSServerRunner::start();
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
  if (verify(status)) {
    JSON recv;
    status = r.getResponse(recv);
    EXPECT_TRUE(status.ok());
  }
}

TEST_F(TLSTransportsTests, test_call_with_params) {
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
  if (verify(status)) {
    JSON recv;
    status = r.getResponse(recv);
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(params.doc(), recv.doc());
  }
}

TEST_F(TLSTransportsTests, DISABLED_test_call_verify_peer) {
  // Create a default request without a transport that accepts invalid peers.
  auto url = "https://localhost:" + port_;
  Request<TLSTransport, JSONSerializer> r(url);

  // The status/call will fail TLS negotiation because our client is trying
  // to verify the fake server, CA, commonName.
  Status status;
  ASSERT_NO_THROW(status = r.call());
  if (verify(status)) {
    EXPECT_FALSE(status.ok());
    // A non-1 exit code means the request failed, but not because of a socket
    // error or request-connection problem.
    EXPECT_EQ(status.getCode(), 2);
    if (!nameError(status)) {
      EXPECT_EQ(status.getMessage(),
                "Request error: certificate verify failed");
    }
  }
}

TEST_F(TLSTransportsTests, test_call_server_cert_pinning) {
  // Require verification but include the server's certificate that includes
  // an unknown signing CA and wrong commonName.
  auto t = std::make_shared<TLSTransport>();
  t->setPeerCertificate((getTestConfigDirectory() / "test_server_ca.pem").string());

  auto url = "https://localhost:" + port_;
  Request<TLSTransport, JSONSerializer> r1(url, t);

  Status status;
  ASSERT_NO_THROW(status = r1.call());
  if (verify(status)) {
    EXPECT_TRUE(status.ok());
  }

  // Now try with a path that is not a filename.
  t = std::make_shared<TLSTransport>();
  t->setPeerCertificate(getTestConfigDirectory().string());
  Request<TLSTransport, JSONSerializer> r2(url, t);

  ASSERT_NO_THROW(status = r2.call());
  if (verify(status)) {
    EXPECT_FALSE(status.ok());
  }
}

TEST_F(TLSTransportsTests, test_call_client_auth) {
  auto t = std::make_shared<TLSTransport>();
  t->setPeerCertificate((getTestConfigDirectory() / "test_server_ca.pem").string());
  t->setClientCertificate((getTestConfigDirectory() / "test_client.pem").string(),
                          (getTestConfigDirectory() / "test_client.key").string());

  auto url = "https://localhost:" + port_;
  Request<TLSTransport, JSONSerializer> r(url, t);

  Status status;
  ASSERT_NO_THROW(status = r.call());
  if (verify(status)) {
    EXPECT_TRUE(status.ok());
  }
}
}
