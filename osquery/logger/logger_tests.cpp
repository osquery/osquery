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
#include <osquery/logger.h>

namespace osquery {

class LoggerTests : public testing::Test {
 public:
  LoggerTests() { Registry::setUp(); }
};

class TestLoggerPlugin : public LoggerPlugin {
 public:
  TestLoggerPlugin() {}

  Status logString(const std::string& s) { return Status(0, s); }

  virtual ~TestLoggerPlugin() {}
};

TEST_F(LoggerTests, test_plugin) {
  Registry::add<TestLoggerPlugin>("logger", "test");
  auto s = Registry::call("logger", "test", {{"string", "foobar"}});
  EXPECT_EQ(s.ok(), true);
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  osquery::initOsquery(argc, argv);
  return RUN_ALL_TESTS();
}
