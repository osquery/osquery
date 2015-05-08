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

#include <boost/network/protocol/http/server.hpp>

#include <gtest/gtest.h>

#include <osquery/enrollment.h>

#include "osquery/dispatcher/dispatcher.h"
#include "osquery/remote/requests.h"
#include "osquery/remote/transports/http.h"
#include "osquery/remote/serializers/json.h"

namespace http = boost::network::http;

namespace osquery {

DECLARE_string(enrollment_uri);
DECLARE_string(enrollment_app_id);

struct TestHTTPEnrollmentHandler;
typedef http::server<TestHTTPEnrollmentHandler> Server;

struct TestHTTPEnrollmentHandler {
  void operator()(Server::request const &request, Server::response &response) {
    response = Server::response::stock_reply(
        Server::response::ok, std::string("{\"enrollment_key\":\"potatoes\"}"));
  }

  void log(Server::string_type const &info) {
    VLOG(1) << "TestHTTPEnrollmentHandler logging";
  }
};

class HTTPEnrollServerRunner : public InternalRunnable {
 public:
  explicit HTTPEnrollServerRunner(std::shared_ptr<Server> server)
      : server_(server) {}

  void start() {
    // Using a dispatcher and runnable allows us to catch and pretty print
    // any socket/service exceptions.
    try {
      server_->run();
    } catch (const std::exception &e) {
      LOG(ERROR) << "Testing HTTP server failed: " << e.what();
    }
  }

 private:
  std::shared_ptr<Server> server_;
};

class RemoteEnrollmentTests : public testing::Test {
 public:
  void SetUp() {
    port_ = std::to_string(rand() % 10000 + 20000);
    TestHTTPEnrollmentHandler handler;
    Server::options opts(handler);

    // Create an HTTP server instance.
    server_ = std::make_shared<Server>(opts.address("127.0.0.1").port(port_));

    // Create a runnable and add it to the dispatcher.
    Dispatcher::addService(std::make_shared<HTTPEnrollServerRunner>(server_));
  }

  ~RemoteEnrollmentTests() {
    server_->stop();
    Dispatcher::joinServices();
  }

 protected:
  std::shared_ptr<Server> server_;
  std::string port_;
};

TEST_F(RemoteEnrollmentTests, test_enroll) {
  // Set the enrollment URI to the server we created.
  FLAGS_enrollment_uri = "http://127.0.0.1:" + port_;
  FLAGS_enrollment_app_id = "just_a_test_id";

  // Call enroll
  PluginRequest request = {
      {"enroll", "1"},
      // 0 enroll if needed, 1 force re-enroll
  };
  PluginResponse resp;
  Status stat = Registry::call("enrollment", "get_key", request, resp);

  // The enrollment server test mostly stresses workflow and code coverage.
  // Occasionally, like with the transports testing, the non-mocked netlib
  // server failed to bind.
  if (stat.ok()) {
    // Verify get key contains the string
    if (resp.size() == 1) {
      EXPECT_EQ(resp[0]["key"], "potatoes");
    } else {
      EXPECT_EQ(resp.size(), 1);
    }
  }
}
}
