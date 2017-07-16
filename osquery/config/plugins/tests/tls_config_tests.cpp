/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <vector>

#include <gtest/gtest.h>

#include <osquery/config.h>
#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/system.h>
#include <osquery/tables.h>

#include "osquery/config/plugins/tls_config.h"
#include "osquery/core/conversions.h"
#include "osquery/core/json.h"
#include "osquery/dispatcher/scheduler.h"
#include "osquery/remote/requests.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/transports/tls.h"
#include "osquery/remote/utility.h"

#include "osquery/tests/test_additional_util.h"
#include "osquery/tests/test_util.h"

namespace pt = boost::property_tree;

namespace osquery {

DECLARE_string(tls_hostname);
DECLARE_bool(enroll_always);
DECLARE_uint64(config_refresh);

class TLSConfigTests : public testing::Test {
 public:
  void SetUp() override {
    TLSServerRunner::start();
    TLSServerRunner::setClientConfig();

    active_ = Registry::get().getActive("config");
    plugin_ = Flag::getValue("config_plugin");
    endpoint_ = Flag::getValue("config_tls_endpoint");
    node_ = Flag::getValue("tls_node_api");
    refresh_ = Flag::getValue("config_refresh");
    enroll_ = FLAGS_enroll_always;

    // Prevent the refresh thread from starting.
    FLAGS_config_refresh = 0;
  }

  void TearDown() override {
    TLSServerRunner::unsetClientConfig();
    TLSServerRunner::stop();

    Flag::updateValue("config_plugin", plugin_);
    Flag::updateValue("config_tls_endpoint", endpoint_);
    Flag::updateValue("tls_node_api", node_);
    Flag::updateValue("config_refresh", refresh_);
    FLAGS_enroll_always = enroll_;
  }

 private:
  std::string active_;
  std::string plugin_;
  std::string endpoint_;
  std::string node_;
  std::string refresh_;
  bool enroll_{false};
};

TEST_F(TLSConfigTests, test_retrieve_config) {
  // Trigger the enroll.
  Flag::updateValue("config_tls_endpoint", "/config");
  Registry::get().setActive("config", "tls");

  // Expect a POST to the /config endpoint.
  // A GET will return different results.
  Config c;
  c.load();

  EXPECT_EQ("d9b4a05d914c81a1ed4ce129928e2d9a0309c753",
            c.getHash("tls_plugin"));

  // Configure the plugin to use the node API.
  Flag::updateValue("tls_node_api", "1");
  Registry::get().setActive("config", "tls");

  PluginResponse response;
  auto status = Registry::call("config", {{"action", "genConfig"}}, response);
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(1U, response.size());

  // The GET and POST results are slightly different.
  EXPECT_EQ("baz", response[0]["tls_plugin"]);
}

TEST_F(TLSConfigTests, test_runner_and_scheduler) {
  Flag::updateValue("config_tls_endpoint", "/config");
  // Will cause another enroll.
  Registry::get().setActive("config", "tls");

  // Seed our instance config with a schedule.
  Config::get().load();

  // Start a scheduler runner for 3 seconds.
  auto t = static_cast<unsigned long int>(getUnixTime());
  Dispatcher::addService(std::make_shared<SchedulerRunner>(t + 1, 1));
  // Reload our instance config.
  Config::get().load();

  Dispatcher::joinServices();
}

TEST_F(TLSConfigTests, test_setup) {
  // Set a cached node key like the code would have set after a successful
  // enroll. Setting both nodeKey and nodeKeyTime emulates the behavior of a
  // successful enroll.
  std::string db_value;
  auto status = setDatabaseValue(kPersistentSettings, "nodeKey", "CachedKey");
  ASSERT_TRUE(status.ok());

  db_value = std::to_string(getUnixTime());
  status = setDatabaseValue(kPersistentSettings, "nodeKeyTime", db_value);
  ASSERT_TRUE(status.ok());

  // TLSConfigPlugin::setUp default case.
  //
  // Make TLSConfigPlugin do a setup
  auto tls_config_plugin = Registry::get().plugin("config", "tls");

  status = tls_config_plugin->setUp();
  ASSERT_TRUE(status.ok());

  // Verify that the setup call resulted in no remote requests.
  pt::ptree response_tree;
  std::string test_read_uri =
      "https://" + Flag::getValue("tls_hostname") + "/test_read_requests";

  auto request = Request<TLSTransport, JSONSerializer>(test_read_uri);
  request.setOption("hostname", Flag::getValue("tls_hostname"));

  status = request.call(pt::ptree());
  ASSERT_TRUE(status.ok());

  status = request.getResponse(response_tree);
  ASSERT_TRUE(status.ok());

  // TLSConfigPlugin should *not* have sent an enroll or any other TLS request
  // It should have used the cached-key
  EXPECT_EQ(response_tree.size(), 0UL);

  status = getDatabaseValue(kPersistentSettings, "nodeKey", db_value);
  ASSERT_TRUE(status.ok());
  EXPECT_STREQ(db_value.c_str(), "CachedKey");

  // TLSConfigPlugin::setUp wih enroll_always set to true
  //
  // Set the enroll_always flag to true. This should force the
  // tls_config_plugin->setUp to go through TLS enrollment
  FLAGS_enroll_always = true;
  status = tls_config_plugin->setUp();
  ASSERT_TRUE(status.ok());

  // Verify that the enroll returned a key different than the one we had
  // artificially cached
  status = getDatabaseValue(kPersistentSettings, "nodeKey", db_value);
  ASSERT_TRUE(status.ok());
  EXPECT_STRNE(db_value.c_str(), "CachedKey");

  // Make sure TLSConfigPlugin called enroll
  status = request.call(pt::ptree());
  ASSERT_TRUE(status.ok());

  status = request.getResponse(response_tree);
  ASSERT_TRUE(status.ok());

  // There should only be one command that should have been posted - an enroll
  EXPECT_EQ(response_tree.size(), 1UL);

  // Verify that it is indeed Enroll
  db_value = response_tree.get<std::string>(".command");
  EXPECT_STREQ(db_value.c_str(), "enroll");
}
}
