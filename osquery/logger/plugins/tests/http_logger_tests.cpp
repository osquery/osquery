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

#include <osquery/core.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/database.h>

#include "osquery/logger/plugins/http_logger.h"

namespace osquery {

DECLARE_string(logger_plugin);
DECLARE_string(database_path);

class HTTPLoggerTests : public testing::Test {
 public:
  std::shared_ptr<HTTPLoggerPlugin> logger_;
  HTTPLoggerTests() { logger_ = std::make_shared<HTTPLoggerPlugin>(); }
  ~HTTPLoggerTests() {
    Registry::setActive("logger", "filesystem");
    initLogger("filesystem");
  }

  void SetUp() {}
  void TearDown() {}
};

TEST_F(HTTPLoggerTests, test_logger_log_status) {
  // This will be printed to stdout.
  std::vector<StatusLogLine> logs;
  struct StatusLogLine log;
  log.severity = O_WARNING;
  log.filename = "/Not/A/Real/Path";
  log.message = "A test error";
  log.line = 0;
  logs.push_back(log);
  logger_->logStatus(logs);
  logger_->logString("A string");
  std::vector<std::string> test;
  auto stat = DBHandle::getInstance()->Scan(kLogs, test);
  EXPECT_TRUE(stat.ok());
  // The second warning status will be sent to the logger plugin.
  EXPECT_EQ(test.size(), 2);
}
}
