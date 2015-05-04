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
  void log(...) {}
};

class RemoteEnrollmentTests : public testing::Test {
 public:
  RemoteEnrollmentTests() {
    auto enroll_port = std::to_string(rand() % 10000 + 10000);
    FLAGS_enrollment_uri = "http://localhost:" + enroll_port;
    FLAGS_enrollment_app_id = "just_a_test_id";
    TestHTTPEnrollmentHandler handler;
    Server::options options(handler);
    server_ = std::make_shared<Server>(
        options.address("127.0.0.1").port(enroll_port));
    t_ =
        std::make_shared<boost::thread>(boost::bind(&Server::run, &(*server_)));
  }

  ~RemoteEnrollmentTests() {
    server_->stop();
    t_->join();
  }

 private:
  std::shared_ptr<Server> server_;
  std::shared_ptr<boost::thread> t_;
};

/*
TEST_F(RemoteEnrollmentTests, test_enroll) {
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
*/
}
