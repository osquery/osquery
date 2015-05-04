/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iostream>
#include <random>
#include <sstream>
#include <thread>

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
            "{ \"schedule\": {\"config_server_launchd\": {\"query\": \"select "
            "* from launchd;\", \"interval\": 3600 }}}"));
  }
  void log(...) {}
};

class HttpConfigTests : public testing::Test {
 public:
  HttpConfigTests() {
    // Create an enrollment endpoint and configuration retrieval endpoint.
    auto enroll_port = rand() % 10000 + 10000;
    auto config_port = enroll_port + 1;
    // Set the URIs.
    FLAGS_enrollment_uri = "http://localhost:" + std::to_string(enroll_port);
    FLAGS_config_enrollment_uri =
        "http://localhost:" + std::to_string(config_port);
    FLAGS_enrollment_app_id = "just_a_test_id";

    // Create two servers + handlers with default options.
    EnrollHTTPHandler enrollment;
    ConfigHTTPHandler config;
    EnrollServer::options opt_enroll(enrollment);
    ConfigServer::options opt_config(config);
    enrollment_server_ = std::make_shared<EnrollServer>(
        opt_enroll.address("127.0.0.1").port(std::to_string(enroll_port)));
    config_server_ = std::make_shared<ConfigServer>(
        opt_config.address("127.0.0.1").port(std::to_string(config_port)));

    // Start each server in a separate service thread.
    config_thread_ = std::make_shared<boost::thread>(
        boost::bind(&ConfigServer::run, &*config_server_));
    enroll_thread_ = std::make_shared<boost::thread>(
        boost::bind(&EnrollServer::run, &*enrollment_server_));
  }

  ~HttpConfigTests() {
    enrollment_server_->stop();
    config_server_->stop();
    enroll_thread_->join();
    config_thread_->join();
  }

 protected:
  std::shared_ptr<EnrollServer> enrollment_server_;
  std::shared_ptr<ConfigServer> config_server_;
  std::shared_ptr<boost::thread> enroll_thread_;
  std::shared_ptr<boost::thread> config_thread_;
};

TEST_F(HttpConfigTests, test_enroll_config) {
  // Change the active config plugin.
  EXPECT_TRUE(Registry::setActive("config", "http").ok());

  // Request the config server to generate a config data.
  PluginResponse response;
  auto stat = Registry::call("config", {{"action", "genConfig"}}, response);
  EXPECT_TRUE(stat.ok());

  // Update the config instance with the content from the server.
  Config::update(response[0]);
  ConfigDataInstance config;
  EXPECT_EQ(config.schedule().count("config_server_launchd"), 1);
}
}
