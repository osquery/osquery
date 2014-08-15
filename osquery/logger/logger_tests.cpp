// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/logger.h"
#include "osquery/logger/plugin.h"

#include <gtest/gtest.h>
#include <glog/logging.h>

using namespace osquery::db;
using namespace osquery::logger;
using osquery::Status;

namespace osquery {
namespace logger {

class LoggerTests : public testing::Test {
public:
  LoggerTests() { osquery::InitRegistry::get().run(); }
};

class TestLoggerPlugin : public LoggerPlugin {
public:
  TestLoggerPlugin() {}

  Status logString(const std::string &s) { return Status(0, s); }

  virtual ~TestLoggerPlugin() {}
};

REGISTER_LOGGER_PLUGIN("test",
                       std::make_shared<osquery::logger::TestLoggerPlugin>());

TEST_F(LoggerTests, test_plugin) {
  auto s = REGISTERED_LOGGER_PLUGINS.at("test")->logString("foobar");
  EXPECT_EQ(s.ok(), true);
  EXPECT_EQ(s.toString(), "foobar");
}
}
}

int main(int argc, char *argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
