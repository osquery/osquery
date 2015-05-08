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

#include "osquery/dispatcher/dispatcher.h"
#include "osquery/remote/requests.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/transports/http.h"

namespace http = boost::network::http;

namespace osquery {

struct TestHTTPTransportHandler;
typedef http::server<TestHTTPTransportHandler> Server;

struct TestHTTPTransportHandler {
  void operator()(Server::request const &request, Server::response &response) {
    response = Server::response::stock_reply(Server::response::ok,
                                             std::string("{\"foo\":\"bar\"}"));
  }

  void log(Server::string_type const &info) {
    VLOG(1) << "TestHTTPTransportHandler logging";
  }
};

class HTTPServerRunner : public InternalRunnable {
 public:
  explicit HTTPServerRunner(std::shared_ptr<Server> server) : server_(server) {}

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

class HTTPTransportsTests : public testing::Test {
 public:
  void SetUp() {
    port_ = std::to_string(rand() % 10000 + 20000);
    TestHTTPTransportHandler handler;
    Server::options opts(handler);

    // Create an HTTP server instance.
    server_ = std::make_shared<Server>(opts.address("127.0.0.1").port(port_));

    // Create a runnable and add it to the dispatcher.
    Dispatcher::addService(std::make_shared<HTTPServerRunner>(server_));
  }

  void TearDown() {
    server_->stop();
    Dispatcher::joinServices();
  }

 protected:
  std::shared_ptr<Server> server_;
  std::string port_;
};

TEST_F(HTTPTransportsTests, test_call) {
  auto r = Request<HTTPTransport, JSONSerializer>("http://127.0.0.1:" + port_);
  Status status;
  ASSERT_NO_THROW(status = r.call());

  // Sometimes the best we can test is the call workflow.
  if (status.ok()) {
    boost::property_tree::ptree params;
    status = r.getResponse(params);
    EXPECT_TRUE(status.ok());
  } else {
    // The socket bind failed.
  }
}

TEST_F(HTTPTransportsTests, test_call_with_params) {
  auto r = Request<HTTPTransport, JSONSerializer>("http://127.0.0.1:" + port_);
  boost::property_tree::ptree params;
  params.put<std::string>("foo", "bar");

  Status status;
  ASSERT_NO_THROW(status = r.call(params));

  if (status.ok()) {
    boost::property_tree::ptree recv;
    auto s2 = r.getResponse(recv);
    EXPECT_TRUE(s2.ok());
    EXPECT_EQ(params, recv);
  } else {
    // The socket bind failed.
  }
}
}
