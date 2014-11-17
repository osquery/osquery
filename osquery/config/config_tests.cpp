// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/config.h"
#include "osquery/config/plugin.h"

#include <gtest/gtest.h>

#include "osquery/core.h"
#include "osquery/status.h"
#include "osquery/registry.h"

using osquery::Status;

namespace osquery {

class ConfigTests : public testing::Test {
 public:
  ConfigTests() { osquery::InitRegistry::get().run(); }
};

TEST_F(ConfigTests, test_queries_execute) {
  auto c = Config::getInstance();
  for (const auto& i : c->getScheduledQueries()) {
    int err;
    auto r = query(i.query, err);
    EXPECT_EQ(err, 0);

    // At most query one shceduled query from the config.
    break;
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

REGISTER_CONFIG_PLUGIN("test", std::make_shared<osquery::TestConfigPlugin>());

TEST_F(ConfigTests, test_plugin) {
  auto p = REGISTERED_CONFIG_PLUGINS.at("test")->genConfig();
  EXPECT_EQ(p.first.ok(), true);
  EXPECT_EQ(p.first.toString(), "OK");
  EXPECT_EQ(p.second, "foobar");
}

TEST_F(ConfigTests, test_splay) {
  auto val1 = Config::splayValue(100, 10);
  EXPECT_GE(val1, 90);
  EXPECT_LE(val1, 110);

  auto val2 = Config::splayValue(100, 10);
  EXPECT_GE(val2, 90);
  EXPECT_LE(val2, 110);

  EXPECT_NE(val1, val2);

  auto val3 = Config::splayValue(10, 0);
  EXPECT_EQ(val3, 10);
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
