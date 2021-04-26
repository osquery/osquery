/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <vector>

#include <gtest/gtest.h>

#include <osquery/config/config.h>
#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/database/database.h>
#include <osquery/dispatcher/scheduler.h>
#include <osquery/hashing/hashing.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry.h>
#include <osquery/remote/requests.h>
#include <osquery/remote/serializers/json.h>
#include <osquery/remote/tests/test_utils.h>
#include <osquery/remote/transports/tls.h>
#include <osquery/utils/system/time.h>
#include <plugins/config/tls_config.h>

namespace osquery {

DECLARE_string(tls_hostname);
DECLARE_bool(enroll_always);
DECLARE_uint64(config_refresh);

class TLSConfigTests : public testing::Test {
 public:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();

    ASSERT_TRUE(TLSServerRunner::start());
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

  // clang-format off
  // Hash for:
  // {"schedule":{"tls_proc":{"query":"select * from processes","interval":1}},"node_invalid":false,"node":true}
  // clang-format on
  EXPECT_EQ("1c70dc4608ed9f8d8e24d23359a46e8739a93558",
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
  {
    auto scheduler_runner = std::make_shared<SchedulerRunner>(1, 1);
    scheduler_runner->request_shutdown_on_expiration = false;

    ASSERT_TRUE(Dispatcher::addService(scheduler_runner).ok());
  }
  // Reload our instance config.
  ASSERT_TRUE(Config::get().load().ok());

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
  JSON response_tree;
  std::string test_read_uri =
      "https://" + Flag::getValue("tls_hostname") + "/test_read_requests";

  Request<TLSTransport, JSONSerializer> request(test_read_uri);
  request.setOption("hostname", Flag::getValue("tls_hostname"));

  status = request.call(JSON());
  ASSERT_TRUE(status.ok());

  status = request.getResponse(response_tree);
  ASSERT_TRUE(status.ok());

  // TLSConfigPlugin should *not* have sent an enroll or any other TLS request
  // It should have used the cached-key
  EXPECT_EQ(response_tree.doc().Size(), 0UL);

  status = getDatabaseValue(kPersistentSettings, "nodeKey", db_value);
  ASSERT_TRUE(status.ok());
  EXPECT_STREQ(db_value.c_str(), "CachedKey");

  // TLSConfigPlugin::setUp with enroll_always set to true
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
  status = request.call(JSON());
  ASSERT_TRUE(status.ok());

  status = request.getResponse(response_tree);
  ASSERT_TRUE(status.ok());

  // There should only be one command that should have been posted - an enroll
  EXPECT_EQ(response_tree.doc().Size(), 1UL);

  auto const& obj = response_tree.doc()[0];
  ASSERT_TRUE(obj.IsObject());

  ASSERT_TRUE(obj.HasMember("command"));
  ASSERT_TRUE(obj["command"].IsString());

  // Verify that it is indeed Enroll
  db_value = obj["command"].GetString();
  EXPECT_STREQ(db_value.c_str(), "enroll");
}
} // namespace osquery
