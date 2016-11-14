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

#include "osquery/core/conversions.h"
#include "osquery/core/json.h"

#include "osquery/remote/requests.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/transports/tls.h"
#include "osquery/remote/utility.h"

#include "osquery/tests/test_additional_util.h"
#include "osquery/tests/test_util.h"

#include "osquery/config/plugins/tls.h"

namespace pt = boost::property_tree;

namespace osquery {

DECLARE_string(tls_hostname);
DECLARE_bool(enroll_always);

class TLSConfigTests : public testing::Test {};

TEST_F(TLSConfigTests, test_retrieve_config) {
  TLSServerRunner::start();
  TLSServerRunner::setClientConfig();

  // Trigger the enroll.
  auto endpoint = Flag::getValue("config_tls_endpoint");
  Flag::updateValue("config_tls_endpoint", "/config");
  Registry::setActive("config", "tls");

  // Expect a POST to the /config endpoint.
  // A GET will return different results.
  Config c;
  c.load();

  const auto& hashes = c.hash_;
  EXPECT_EQ("b7718020a76ced2eda82336bd15165009603d4fb",
            hashes.at("tls_plugin"));

  // Configure the plugin to use the node API.
  Flag::updateValue("tls_node_api", "1");
  Registry::setActive("config", "tls");

  PluginResponse response;
  auto status = Registry::call("config", {{"action", "genConfig"}}, response);
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(1U, response.size());

  // The GET and POST results are slightly different.
  EXPECT_EQ("baz", response[0]["tls_plugin"]);

  // Clean up.
  Flag::updateValue("tls_node_api", "0");
  Flag::updateValue("config_tls_endpoint", endpoint);
  TLSServerRunner::unsetClientConfig();
  TLSServerRunner::stop();
}

TEST_F(TLSConfigTests, test_setup) {
  // Start a server.
  TLSServerRunner::start();
  TLSServerRunner::setClientConfig();

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
  auto tls_config_plugin = Registry::get("config", "tls");

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

  // Stop the server.
  TLSServerRunner::unsetClientConfig();
  TLSServerRunner::stop();
}
}
