/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <random>
#include <thread>

#include <signal.h>

#include <gtest/gtest.h>

#include <boost/noncopyable.hpp>

#include <osquery/logger.h>

#include "osquery/remote/requests.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/transports/tls.h"

#include "osquery/core/test_util.h"

namespace pt = boost::property_tree;

namespace osquery {

class TLSServerRunner : private boost::noncopyable {
 public:
  /// Create a singleton TLS server runner.
  static TLSServerRunner& instance() {
    static TLSServerRunner instance;
    return instance;
  }

  /// TCP port accessor.
  static const std::string& port() { return instance().port_; }
  /// Start the server if it hasn't started already.
  static void start();
  /// Stop the service when the process exits.
  static void stop();

 private:
  TLSServerRunner()
      : server_(0), port_(std::to_string(rand() % 10000 + 20000)){};
  TLSServerRunner(TLSServerRunner const&);
  void operator=(TLSServerRunner const&);
  virtual ~TLSServerRunner() { stop(); }

 private:
  pid_t server_;
  std::string port_;
};

void TLSServerRunner::start() {
  auto& self = instance();
  if (self.server_ != 0) {
    return;
  }

  // Fork then exec a shell.
  self.server_ = fork();
  if (self.server_ == 0) {
    // Start a python TLS/HTTPS or HTTP server.
    auto script = kTestDataPath + "/test_http_server.py --tls " + self.port_;
    execlp("sh", "sh", "-c", script.c_str(), nullptr);
    ::exit(0);
  }
  ::sleep(1);
}

void TLSServerRunner::stop() {
  auto& self = instance();
  kill(self.server_, SIGTERM);
}

class TLSTransportsTests : public testing::Test {
 public:
  bool verify(const Status &status) {
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

  void SetUp() {
    TLSServerRunner::start();
    port_ = TLSServerRunner::port();
  }

 protected:
  std::string port_;
};

TEST_F(TLSTransportsTests, test_call) {
  // Create a transport and use a testing-only 'disableVerifyPeer' call.
  // This allows our client to complete TLS without verifying the fake
  // commonName or fake CA used by the testing server.
  auto t = std::make_shared<TLSTransport>();
  t->disableVerifyPeer();

  // Create a request using a TLSTransport and JSONSerializer.
  auto url = "https://localhost:" + port_;
  auto r = Request<TLSTransport, JSONSerializer>(url, t);

  // Use the 'call' method on the request without any input parameters.
  // This will use a GET for the URI given in the Request constructor.
  Status status;
  ASSERT_NO_THROW(status = r.call());
  if (verify(status)) {
    pt::ptree recv;
    status = r.getResponse(recv);
    EXPECT_TRUE(status.ok());
  }
}

TEST_F(TLSTransportsTests, test_call_with_params) {
  // Again, use a fake server/CA/commonName certificate.
  auto t = std::make_shared<TLSTransport>();
  t->disableVerifyPeer();

  auto url = "https://localhost:" + port_;
  auto r = Request<TLSTransport, JSONSerializer>(url, t);

  // This time we'll construct a request parameter.
  pt::ptree params;
  params.put<std::string>("foo", "bar");

  // The call with a set of a params will push this "JSONSerializer"-serialized
  // data into the body of the request and issue a POST to the URI.
  Status status;
  ASSERT_NO_THROW(status = r.call(params));
  if (verify(status)) {
    pt::ptree recv;
    status = r.getResponse(recv);
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(params, recv);
  }
}

TEST_F(TLSTransportsTests, test_call_verify_peer) {
  // Create a default request without a transport that accepts invalid peers.
  auto url = "https://localhost:" + port_;
  auto r = Request<TLSTransport, JSONSerializer>(url);

  // The status/call will fail TLS negotiation because our client is trying
  // to verify the fake server, CA, commonName.
  Status status;
  ASSERT_NO_THROW(status = r.call());
  if (verify(status)) {
    EXPECT_FALSE(status.ok());
    // A non-1 exit code means the request failed, but not because of a socket
    // error or request-connection problem.
    EXPECT_EQ(status.getCode(), 2);
    EXPECT_EQ(status.getMessage(), "Request error: certificate verify failed");
  }
}

TEST_F(TLSTransportsTests, test_call_server_cert_pinning) {
  // Require verification but include the server's certificate that includes
  // an unknown signing CA and wrong commonName.
  auto t = std::make_shared<TLSTransport>();
  t->setPeerCertificate(kTestDataPath + "test_server_ca.pem");

  auto url = "https://localhost:" + port_;
  auto r = Request<TLSTransport, JSONSerializer>(url, t);

  Status status;
  ASSERT_NO_THROW(status = r.call());
  if (verify(status)) {
    EXPECT_TRUE(status.ok());
  }

  // Now try with a path that is not a filename.
  t = std::make_shared<TLSTransport>();
  t->setPeerCertificate(kTestDataPath);
  r = Request<TLSTransport, JSONSerializer>(url, t);

  ASSERT_NO_THROW(status = r.call());
  if (verify(status)) {
    EXPECT_FALSE(status.ok());
  }
}

TEST_F(TLSTransportsTests, test_call_client_auth) {
  auto t = std::make_shared<TLSTransport>();
  t->setPeerCertificate(kTestDataPath + "test_server_ca.pem");
  t->setClientCertificate(kTestDataPath + "test_client.pem",
                          kTestDataPath + "test_client.key");

  auto url = "https://localhost:" + port_;
  auto r = Request<TLSTransport, JSONSerializer>(url, t);

  Status status;
  ASSERT_NO_THROW(status = r.call());
  if (verify(status)) {
    EXPECT_TRUE(status.ok());
  }
}

TEST_F(TLSTransportsTests, test_request_http_client_internals) {
  auto url = "https://localhost:" + port_;
  auto r = Request<TLSTransport, JSONSerializer>(url);
  auto r2 = Request<TLSTransport, JSONSerializer>(url);
}
}
