// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/config.h"
#include "osquery/config/plugin.h"

#include <gtest/gtest.h>

#include "osquery/core.h"
#include "osquery/status.h"
#include "osquery/registry.h"

namespace core = osquery::core;
using osquery::Status;

namespace osquery { namespace config {

class ConfigTests : public testing::Test {
public:
  ConfigTests() {
    osquery::InitRegistry::get().run();
  }
};

TEST_F(ConfigTests, test_queries_execute) {
  auto c = Config::getInstance();
  for (const auto& i : c->getScheduledQueries()) {
    int err;
    auto r = core::aggregateQuery(i.query, err);
    EXPECT_EQ(err, 0);
  }
}

class TestConfigPlugin : public ConfigPlugin {
public:
  TestConfigPlugin() {}

  std::pair<Status, std::string> genConfig() {
    return std::make_pair(Status(0, "OK"), "foobar");
  }

  virtual ~TestConfigPlugin() {}
};

REGISTER_CONFIG_PLUGIN(
  "test",
  std::make_shared<osquery::config::TestConfigPlugin>()
);

TEST_F(ConfigTests, test_plugin) {
  auto p = REGISTERED_CONFIG_PLUGINS.at("test")->genConfig();
  EXPECT_EQ(p.first.ok(), true);
  EXPECT_EQ(p.first.toString(), "OK");
  EXPECT_EQ(p.second, "foobar");
}

}}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
