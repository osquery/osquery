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

#include <osquery/enrollment.h>
#include "osquery/remote/requests.h"
#include "osquery/remote/transports/http.h"
#include "osquery/remote/serializers/json.h"

namespace http = boost::network::http;

namespace osquery {

DECLARE_string(enrollment_uri);
DECLARE_string(enrollment_app_id);

class EnrollmentTests : public testing::Test {
 public:
  void SetUp() {}
};

struct FooBarHTTPHandler;
typedef http::server<FooBarHTTPHandler> Server;

struct FooBarHTTPHandler {
  void operator()(Server::request const &request, Server::response &response) {
    response = Server::response::stock_reply(
        Server::response::ok, std::string("{\"enrollment_key\":\"potatoes\"}"));
  }
  void log(...) {}
};

TEST_F(EnrollmentTests, test_enroll) {
  // Call enroll
  PluginRequest request = {
      {"enroll", "1"}, // 0 enroll if needed, 1 force re-enroll
  };
  PluginResponse resp;
  Status stat = Registry::call("enrollment", "get_key", request, resp);
  EXPECT_TRUE(stat.ok());
  // Verify get key contains the string
  if (resp.size() == 1) {
    EXPECT_EQ(resp[0]["key"], "potatoes");
  } else {
    EXPECT_EQ(resp.size(), 1);
  }
}
}

int main(int argc, char *argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  osquery::FLAGS_enrollment_uri = "http://localhost:8241";
  osquery::FLAGS_enrollment_app_id = "just_a_test_id";
  osquery::FooBarHTTPHandler handler;
  osquery::Server::options options(handler);
  osquery::Server server(options.address("127.0.0.1").port("8241"));
  boost::thread t(boost::bind(&osquery::Server::run, &server));
  auto ret = RUN_ALL_TESTS();
  server.stop();
  t.join();
  return ret;
}
