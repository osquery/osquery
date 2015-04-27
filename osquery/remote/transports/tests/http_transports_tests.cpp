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

  void log(...) {}
};

class HTTPTransportsTests : public testing::Test {
 public:
  HTTPTransportsTests() {
    port_ = std::to_string(rand() % 10000 + 10000);
    TestHTTPTransportHandler handler;
    Server::options options(handler);
    server_ =
        std::make_shared<Server>(options.address("127.0.0.1").port(port_));
    t_ =
        std::make_shared<boost::thread>(boost::bind(&Server::run, &(*server_)));
  }

  ~HTTPTransportsTests() {
    server_->stop();
    t_->join();
  }

 protected:
  std::shared_ptr<Server> server_;
  std::shared_ptr<boost::thread> t_;
  std::string port_;
};

TEST_F(HTTPTransportsTests, test_call) {
  auto r = Request<HTTPTransport, JSONSerializer>("http://127.0.0.1:" + port_);
  auto s1 = r.call();
  EXPECT_TRUE(s1.ok());
  boost::property_tree::ptree params;
  auto s2 = r.getResponse(params);
  EXPECT_TRUE(s2.ok());
}

TEST_F(HTTPTransportsTests, test_call_with_params) {
  auto r = Request<HTTPTransport, JSONSerializer>("http://127.0.0.1:" + port_);
  boost::property_tree::ptree params;
  params.put<std::string>("foo", "bar");
  auto s1 = r.call(params);
  EXPECT_TRUE(s1.ok());

  boost::property_tree::ptree recv;
  auto s2 = r.getResponse(recv);
  EXPECT_TRUE(s2.ok());
  EXPECT_EQ(params, recv);
}
}
