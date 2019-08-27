/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <gtest/gtest.h>

#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/registry_interface.h>
#include <osquery/remote/tests/test_utils.h>
#include <osquery/system.h>

#include "plugins/logger/tls_logger.h"

namespace osquery {
DECLARE_bool(disable_database);

class TLSLoggerTests : public testing::Test {
 protected:
  void SetUp() {
    Initializer::platformSetup();
    registryAndPluginInit();
    FLAGS_disable_database = true;
    DatabasePlugin::setAllowOpen(true);
    DatabasePlugin::initPlugin();
  }

 public:
  void runCheck(const std::shared_ptr<TLSLogForwarder>& runner) {
    runner->check();
  }
};

TEST_F(TLSLoggerTests, test_database) {
  // Start a server.
  TLSServerRunner::start();
  TLSServerRunner::setClientConfig();

  auto forwarder = std::make_shared<TLSLogForwarder>();
  std::string expected = "{\"new_json\": true}";
  forwarder->logString(expected);
  StatusLogLine status{};
  status.message = "{\"status\": \"bar\"}";
  forwarder->logStatus({status});

  // Stop the server.
  TLSServerRunner::unsetClientConfig();
  TLSServerRunner::stop();

  std::vector<std::string> indexes;
  scanDatabaseKeys(kLogs, indexes);
  EXPECT_EQ(2U, indexes.size());

  // Iterate using an unordered search, and search for the expected string
  // that was just logged.
  bool found_string = false;
  for (const auto& index : indexes) {
    std::string value;
    getDatabaseValue(kLogs, index, value);
    found_string = (found_string || value == expected);
    deleteDatabaseValue(kLogs, index);
  }
  EXPECT_TRUE(found_string);
}

TEST_F(TLSLoggerTests, test_send) {
  // Start a server.
  TLSServerRunner::start();
  TLSServerRunner::setClientConfig();

  auto forwarder = std::make_shared<TLSLogForwarder>();
  for (size_t i = 0; i < 20; i++) {
    std::string expected = "{\"more_json\": true}";
    forwarder->logString(expected);
  }

  runCheck(forwarder);

  // Stop the server.
  TLSServerRunner::unsetClientConfig();
  TLSServerRunner::stop();
}
} // namespace osquery
