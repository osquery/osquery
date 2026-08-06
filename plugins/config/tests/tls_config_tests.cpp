/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <memory>
#include <mutex>
#include <vector>

#include <gtest/gtest.h>

#include <osquery/config/config.h>
#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/database/database.h>
#include <osquery/dispatcher/scheduler.h>
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
DECLARE_bool(config_tls_etag);

/**
 * @brief Helper to POST JSON to the test server and return the JSON response.
 *
 * Uses the standard osquery Request<TLSTransport, JSONSerializer> pattern
 * for test-server communication.
 */
static JSON postToTestServer(const std::string& path,
                             const JSON& body = JSON()) {
  std::string url = "https://" + Flag::getValue("tls_hostname") + path;

  Request<TLSTransport, JSONSerializer> request(url);
  request.setOption("hostname", Flag::getValue("tls_hostname"));

  auto status = request.call(body);
  if (!status.ok()) {
    ADD_FAILURE() << status.getMessage();
    JSON empty;
    return empty;
  }

  JSON response;
  status = request.getResponse(response);
  if (!status.ok()) {
    ADD_FAILURE() << status.getMessage();
  }
  return response;
}

class TLSConfigTests : public testing::Test {
 public:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();

    ASSERT_TRUE(TLSServerRunner::start());
    TLSServerRunner::setClientConfig();

    // Clear any etag state left over from a previous test case.
    // The registered TLSConfigPlugin instance persists across fixture cases.
    {
      auto tls_plugin = std::dynamic_pointer_cast<TLSConfigPlugin>(
          Registry::get().plugin("config", "tls"));
      if (tls_plugin != nullptr) {
        std::lock_guard<std::mutex> lock(tls_plugin->mutex_);
        tls_plugin->etag_.clear();
        tls_plugin->applied_ = false;
      }
    }

    active_ = Registry::get().getActive("config");
    plugin_ = Flag::getValue("config_plugin");
    endpoint_ = Flag::getValue("config_tls_endpoint");
    node_ = Flag::getValue("tls_node_api");
    refresh_ = Flag::getValue("config_refresh");
    enroll_ = FLAGS_enroll_always;
    etag_ = FLAGS_config_tls_etag;

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
    FLAGS_config_tls_etag = etag_;
  }

 protected:
  std::unique_ptr<TLSConfigPlugin> createETagPlugin(bool enabled = true,
                                                    bool node_api = false) {
    postToTestServer("/reset_config_test_state");
    Flag::updateValue("config_tls_endpoint", "/config");
    Flag::updateValue("config_tls_etag", enabled ? "1" : "0");
    Flag::updateValue("tls_node_api", node_api ? "1" : "0");

    auto plugin = std::make_unique<TLSConfigPlugin>();
    EXPECT_TRUE(plugin->setUp().ok());
    return plugin;
  }

  JSON getETagEvents() {
    return postToTestServer("/read_etag_events");
  }

  void setConfigPayload(const std::string& json) {
    JSON payload;
    ASSERT_TRUE(payload.fromString(json).ok());
    postToTestServer("/set_config_payload", payload);
  }

  void setEtagMode(const std::string& mode) {
    JSON request;
    request.addCopy("mode", mode);
    postToTestServer("/set_config_etag_mode", request);
  }

 private:
  std::string active_;
  std::string plugin_;
  std::string endpoint_;
  std::string node_;
  std::string refresh_;
  bool enroll_{false};
  bool etag_{true};
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

TEST_F(TLSConfigTests, test_etag_full_then_unchanged) {
  auto plugin = createETagPlugin();

  std::map<std::string, std::string> first_config;
  ASSERT_TRUE(plugin->genConfig(first_config).ok());
  const auto baseline_config = first_config.at("tls_plugin");
  EXPECT_NE(baseline_config.find("\"schedule\""), std::string::npos);
  // The etag key is stripped before the config is applied.
  EXPECT_EQ(baseline_config.find("\"etag\""), std::string::npos);

  // The refresh path reports a successful update back to the plugin.
  ASSERT_TRUE(plugin->configApplied().ok());

  std::map<std::string, std::string> second_config;
  auto status = plugin->genConfig(second_config);
  EXPECT_EQ(status.getCode(), 2);
  EXPECT_TRUE(second_config.empty());

  auto events = getETagEvents();
  ASSERT_EQ(events.doc().Size(), 2UL);
  // The first request opts in with an empty etag and downloads the config.
  ASSERT_TRUE(events.doc()[0]["request_etag"].IsString());
  EXPECT_STREQ(events.doc()[0]["request_etag"].GetString(), "");
  ASSERT_TRUE(events.doc()[0]["etag"].IsString());
  EXPECT_FALSE(events.doc()[0]["not_modified"].GetBool());
  // The second echoes the server's etag and receives the minimal body.
  ASSERT_TRUE(events.doc()[1]["request_etag"].IsString());
  EXPECT_STREQ(events.doc()[1]["request_etag"].GetString(),
               events.doc()[0]["etag"].GetString());
  EXPECT_TRUE(events.doc()[1]["not_modified"].GetBool());
  EXPECT_LT(events.doc()[1]["body_size"].GetInt(),
            events.doc()[0]["body_size"].GetInt());
}

TEST_F(TLSConfigTests, test_etag_payload_change) {
  auto plugin = createETagPlugin();

  std::map<std::string, std::string> config;
  ASSERT_TRUE(plugin->genConfig(config).ok());
  const auto baseline_config = config.at("tls_plugin");
  ASSERT_TRUE(plugin->configApplied().ok());

  setConfigPayload(
      R"({"payload":{"schedule":{"tls_proc":{"query":"select * from processes","interval":10}},"auto_table_construction":{"quarantine_items":{"query":"SELECT 1","path":"/tmp","columns":["path"]}},"node_invalid":false}})");

  std::map<std::string, std::string> changed_config;
  ASSERT_TRUE(plugin->genConfig(changed_config).ok());
  EXPECT_NE(changed_config.at("tls_plugin"), baseline_config);
  EXPECT_NE(changed_config.at("tls_plugin").find("auto_table_construction"),
            std::string::npos);
  EXPECT_EQ(changed_config.at("tls_plugin").find("\"etag\""),
            std::string::npos);
  ASSERT_TRUE(plugin->configApplied().ok());

  std::map<std::string, std::string> unchanged_config;
  EXPECT_EQ(plugin->genConfig(unchanged_config).getCode(), 2);
  EXPECT_TRUE(unchanged_config.empty());

  auto events = getETagEvents();
  ASSERT_EQ(events.doc().Size(), 3UL);
  // A stale etag downloads the new config with a new etag.
  EXPECT_FALSE(events.doc()[1]["not_modified"].GetBool());
  EXPECT_STREQ(events.doc()[1]["request_etag"].GetString(),
               events.doc()[0]["etag"].GetString());
  EXPECT_STRNE(events.doc()[1]["etag"].GetString(),
               events.doc()[0]["etag"].GetString());
  // The new etag is current.
  EXPECT_TRUE(events.doc()[2]["not_modified"].GetBool());
  EXPECT_STREQ(events.doc()[2]["request_etag"].GetString(),
               events.doc()[1]["etag"].GetString());
}

TEST_F(TLSConfigTests, test_etag_disabled) {
  auto plugin = createETagPlugin(false);

  std::map<std::string, std::string> config;
  ASSERT_TRUE(plugin->genConfig(config).ok());
  ASSERT_FALSE(config.at("tls_plugin").empty());
  ASSERT_TRUE(plugin->genConfig(config).ok());

  auto events = getETagEvents();
  ASSERT_EQ(events.doc().Size(), 2UL);
  for (const auto& event : events.doc().GetArray()) {
    // The request does not opt in and the response carries no etag.
    EXPECT_TRUE(event["request_etag"].IsNull());
    EXPECT_TRUE(event["etag"].IsNull());
    EXPECT_FALSE(event["not_modified"].GetBool());
  }
}

TEST_F(TLSConfigTests, test_etag_node_api) {
  auto plugin = createETagPlugin(true, true);

  // The node API is a GET without a body; it cannot participate in
  // conditional requests and always receives the full config.
  std::map<std::string, std::string> config;
  ASSERT_TRUE(plugin->genConfig(config).ok());
  EXPECT_EQ(config.at("tls_plugin"), "baz");

  std::map<std::string, std::string> second_config;
  ASSERT_TRUE(plugin->genConfig(second_config).ok());
  EXPECT_EQ(second_config.at("tls_plugin"), "baz");

  auto events = getETagEvents();
  EXPECT_EQ(events.doc().Size(), 0UL);
}

TEST_F(TLSConfigTests, test_etag_bad_config_not_redownloaded) {
  auto plugin = createETagPlugin();

  std::map<std::string, std::string> config;
  ASSERT_TRUE(plugin->genConfig(config).ok());
  // The config is never reported as applied, as if Config::update()
  // rejected it.

  // The server's config is unchanged: it is not downloaded again, and the
  // refresh fails loudly instead of masking the rejected config.
  for (auto i = 0; i < 2; i++) {
    std::map<std::string, std::string> unchanged_config;
    auto status = plugin->genConfig(unchanged_config);
    EXPECT_FALSE(status.ok());
    EXPECT_NE(status.getCode(), 2);
    EXPECT_NE(status.getMessage().find("failed to apply"), std::string::npos);
    EXPECT_TRUE(unchanged_config.empty());
  }

  auto events = getETagEvents();
  ASSERT_EQ(events.doc().Size(), 3UL);
  EXPECT_FALSE(events.doc()[0]["not_modified"].GetBool());
  EXPECT_TRUE(events.doc()[1]["not_modified"].GetBool());
  EXPECT_TRUE(events.doc()[2]["not_modified"].GetBool());

  // A fixed server config downloads, applies, and recovers.
  setConfigPayload(
      R"({"payload":{"schedule":{"tls_proc":{"query":"select * from processes","interval":10}},"node_invalid":false}})");

  std::map<std::string, std::string> fixed_config;
  ASSERT_TRUE(plugin->genConfig(fixed_config).ok());
  EXPECT_NE(fixed_config.at("tls_plugin"), config.at("tls_plugin"));
  ASSERT_TRUE(plugin->configApplied().ok());

  std::map<std::string, std::string> unchanged_config;
  EXPECT_EQ(plugin->genConfig(unchanged_config).getCode(), 2);
}

TEST_F(TLSConfigTests, test_etag_old_server) {
  auto plugin = createETagPlugin();
  setEtagMode("off");

  // A server that ignores the etag field behaves exactly as today.
  std::map<std::string, std::string> config;
  ASSERT_TRUE(plugin->genConfig(config).ok());
  EXPECT_EQ(config.at("tls_plugin").find("\"etag\""), std::string::npos);
  ASSERT_TRUE(plugin->configApplied().ok());

  std::map<std::string, std::string> second_config;
  ASSERT_TRUE(plugin->genConfig(second_config).ok());
  EXPECT_EQ(second_config, config);

  auto events = getETagEvents();
  ASSERT_EQ(events.doc().Size(), 2UL);
  for (const auto& event : events.doc().GetArray()) {
    // The plugin keeps opting in with an empty etag; nothing is stored
    // from responses that assign no etag.
    ASSERT_TRUE(event["request_etag"].IsString());
    EXPECT_STREQ(event["request_etag"].GetString(), "");
    EXPECT_TRUE(event["etag"].IsNull());
    EXPECT_FALSE(event["not_modified"].GetBool());
  }
}

TEST_F(TLSConfigTests, test_etag_ok_without_history) {
  auto plugin = createETagPlugin();
  setEtagMode("always_ok");

  // A server may not signal an unchanged config to an agent that has not
  // echoed one of its etags; nothing is applied.
  std::map<std::string, std::string> config;
  auto status = plugin->genConfig(config);
  EXPECT_FALSE(status.ok());
  EXPECT_NE(status.getCode(), 2);
  EXPECT_TRUE(config.empty());
}
} // namespace osquery
