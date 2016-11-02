/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/config.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry.h>

#include "osquery/tests/test_additional_util.h"
#include "osquery/tests/test_util.h"

namespace osquery {

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
  EXPECT_EQ("c109cd4fc0a928dba787384a89f9d03d", hashes.at("tls_plugin"));

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
}
