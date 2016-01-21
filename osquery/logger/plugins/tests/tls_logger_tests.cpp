/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/logger.h>
#include <osquery/database.h>

#include "osquery/core/test_util.h"

#include "osquery/logger/plugins/tls.h"

namespace pt = boost::property_tree;

namespace osquery {

class TLSLoggerTests : public testing::Test {
 public:
  size_t getIndex(const std::shared_ptr<TLSLoggerPlugin>& plugin) {
    return plugin->log_index_;
  }

  void runCheck(const std::shared_ptr<TLSLogForwarderRunner>& runner) {
    runner->check();
  }
};

TEST_F(TLSLoggerTests, test_log) {
  auto plugin = std::make_shared<TLSLoggerPlugin>();

  std::vector<StatusLogLine> status;
  status.push_back({O_INFO, "test.cpp", 0, "test"});
  auto s = plugin->logStatus(status);
  EXPECT_TRUE(s.ok());
  // A single status log should have advanced the index by 1.
  EXPECT_EQ(getIndex(plugin), 1U);

  s = plugin->logString("{\"json\": true}");
  EXPECT_TRUE(s.ok());
  // The index is shared between statuses and strings.
  EXPECT_EQ(getIndex(plugin), 2U);
}

TEST_F(TLSLoggerTests, test_database) {
  auto plugin = std::make_shared<TLSLoggerPlugin>();
  std::string expected = "{\"new_json\": true}";
  plugin->logString(expected);

  std::vector<std::string> indexes;
  scanDatabaseKeys(kLogs, indexes);
  EXPECT_EQ(indexes.size(), 3U);

  // Iterate using an unordered search, and search for the expected string
  // that was just logged.
  bool found_string = false;
  for (const auto& index : indexes) {
    std::string value;
    getDatabaseValue(kLogs, index, value);
    found_string = (found_string || value == expected);
  }
  EXPECT_TRUE(found_string);
}

TEST_F(TLSLoggerTests, test_send) {
  auto plugin = std::make_shared<TLSLoggerPlugin>();
  for (size_t i = 0; i < 20; i++) {
    std::string expected = "{\"more_json\": true}";
    plugin->logString(expected);
  }

  // Start a server.
  TLSServerRunner::start();
  TLSServerRunner::setClientConfig();

  // The runner should be dispatched as an osquery service.
  auto runner = std::make_shared<TLSLogForwarderRunner>("fake_key");
  runCheck(runner);

  // Stop the server.
  TLSServerRunner::unsetClientConfig();
  TLSServerRunner::stop();
}
}
