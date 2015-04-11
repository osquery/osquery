/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <thread>

#include <boost/network/protocol/http/server.hpp>
#include <gtest/gtest.h>

#include "osquery/remote/requests.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/transports/http.h"

namespace http = boost::network::http;

namespace osquery {

struct FooBarHTTPHandler;
typedef http::server<FooBarHTTPHandler> Server;

struct FooBarHTTPHandler {
  void operator()(Server::request const &request, Server::response &response) {
    response = Server::response::stock_reply(Server::response::ok,
                                             std::string("{\"foo\":\"bar\"}"));
  }

  void log(...) {}
};

class HTTPTests : public testing::Test {};

TEST_F(HTTPTests, testCall) {
  auto r = Request<HTTPTransport, JSONSerializer>("http://127.0.0.1:8237");
  auto s1 = r.call();
  EXPECT_TRUE(s1.ok());
  boost::property_tree::ptree params;
  auto s2 = r.getResponse(params);
  EXPECT_TRUE(s2.ok());
}

TEST_F(HTTPTests, testCallWithParams) {
  auto r = Request<HTTPTransport, JSONSerializer>("http://127.0.0.1:8237");
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

int main(int argc, char *argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);

  osquery::FooBarHTTPHandler handler;
  osquery::Server::options options(handler);
  osquery::Server server(options.address("127.0.0.1").port("8237"));
  boost::thread t(boost::bind(&osquery::Server::run, &server));
  auto ret = RUN_ALL_TESTS();
  server.stop();
  t.join();
  return ret;
}
