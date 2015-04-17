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
#include <iostream>
#include <sstream>

#include <boost/network/protocol/http/server.hpp>
#include <boost/property_tree/ptree.hpp>
#include <gtest/gtest.h>

#include <osquery/config.h>
#include <osquery/enrollment.h>
#include "osquery/remote/requests.h"
#include "osquery/remote/transports/http.h"
#include "osquery/remote/serializers/json.h"

namespace http = boost::network::http;

namespace osquery {

DECLARE_string(enrollment_uri);
DECLARE_string(config_enrollment_uri);
DECLARE_string(enrollment_app_id);

class HttpConfigTests : public testing::Test {
 public:
  void SetUp() {}
};

struct EnrollHTTPHandler;
struct ConfigHTTPHandler;
typedef http::server<EnrollHTTPHandler> EnrollServer;
typedef http::server<ConfigHTTPHandler> ConfigServer;

struct EnrollHTTPHandler {
  void operator()(EnrollServer::request const &request,
                  EnrollServer::response &response) {
    response = EnrollServer::response::stock_reply(
        EnrollServer::response::ok,
        std::string("{\"enrollment_key\":\"potatoes\"}"));
  }
  void log(...) {}
};

struct ConfigHTTPHandler {
  void operator()(ConfigServer::request const &request,
                  ConfigServer::response &response) {
    response = ConfigServer::response::stock_reply(
        ConfigServer::response::ok,
        std::string(
            "{ \"schedule\": { \"launchd\": { \"query\": \"select * from "
            "launchd;\", \"interval\": 3600 }, \"all_kexts\": { \"query\": "
            "\"select name, version from kextstat;\", \"interval\": 600 } } "
            "}"));
  }
  void log(...) {}
};

TEST_F(HttpConfigTests, test_enroll_config) {
  // Change the active config plugin.
  EXPECT_TRUE(Registry::setActive("config", "http").ok());

  PluginResponse response;
  auto stat = Registry::call("config", {{"action", "genConfig"}}, response);
  EXPECT_TRUE(stat.ok());
  Config::update(response[0]);
  ConfigDataInstance config;
  EXPECT_EQ(config.schedule().size(), 2);
}
}

int main(int argc, char *argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  osquery::FLAGS_enrollment_uri = "http://localhost:8851";
  osquery::FLAGS_config_enrollment_uri = "http://localhost:8852";
  osquery::FLAGS_enrollment_app_id = "just_a_test_id";

  osquery::EnrollHTTPHandler enrollment;
  osquery::ConfigHTTPHandler config;
  osquery::EnrollServer::options opt_enroll(enrollment);
  osquery::ConfigServer::options opt_config(config);
  osquery::EnrollServer enrollment_server(
      opt_enroll.address("127.0.0.1").port("8851"));
  osquery::ConfigServer config_server(
      opt_config.address("127.0.0.1").port("8852"));

  boost::thread enroll_thread(
      boost::bind(&osquery::EnrollServer::run, &enrollment_server)),
      config_thread(boost::bind(&osquery::ConfigServer::run, &config_server));
  auto ret = RUN_ALL_TESTS();

  // Clean up
  enrollment_server.stop();
  config_server.stop();
  enroll_thread.join();
  config_thread.join();
  return ret;
}
