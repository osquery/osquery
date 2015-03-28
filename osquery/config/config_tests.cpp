/*
 *  Copyright (c) 2014, Facebook, Inc.
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
#include <osquery/core.h>
#include <osquery/flags.h>
#include <osquery/registry.h>
#include <osquery/sql.h>

#include "osquery/core/test_util.h"

namespace osquery {

// The config_path flag is defined in the filesystem config plugin.
DECLARE_string(config_path);

class ConfigTests : public testing::Test {
 public:
  ConfigTests() {
    Registry::setActive("config", "filesystem");
    FLAGS_config_path = kTestDataPath + "test.config";
  }

 protected:
  void SetUp() {
    createMockFileStructure();
    Registry::setUp();
    Config::load();
  }

  void TearDown() { tearDownMockFileStructure(); }
};

class TestConfigPlugin : public ConfigPlugin {
 public:
  TestConfigPlugin() {}
  Status genConfig(std::map<std::string, std::string>& config) {
    config["data"] = "foobar";
    return Status(0, "OK");
    ;
  }
};

TEST_F(ConfigTests, test_plugin) {
  Registry::add<TestConfigPlugin>("config", "test");

  // Change the active config plugin.
  EXPECT_TRUE(Registry::setActive("config", "test").ok());

  PluginResponse response;
  auto status = Registry::call("config", {{"action", "genConfig"}}, response);

  EXPECT_EQ(status.ok(), true);
  EXPECT_EQ(status.toString(), "OK");
  EXPECT_EQ(response[0].at("data"), "foobar");
}

TEST_F(ConfigTests, test_queries_execute) {
  ConfigDataInstance config;
  EXPECT_EQ(config.schedule().size(), 2);
}

TEST_F(ConfigTests, test_watched_files) {
  ConfigDataInstance config;
  EXPECT_EQ(config.files().size(), 2);
  EXPECT_EQ(config.files().at("downloads").size(), 1);
  EXPECT_EQ(config.files().at("system_binaries").size(), 2);
}

TEST_F(ConfigTests, test_locking) {
  {
    // Assume multiple instance accessors will be active.
    ConfigDataInstance config1;
    ConfigDataInstance config2;

    // But a unique lock cannot be aquired.
    boost::unique_lock<boost::shared_mutex> lock(Config::getInstance().mutex_,
                                                 boost::defer_lock);

    ASSERT_FALSE(lock.try_lock());
  }

  {
    // However, a unique lock can be obtained when without instances accessors.
    boost::unique_lock<boost::shared_mutex> lock(Config::getInstance().mutex_,
                                                 boost::defer_lock);
    ASSERT_TRUE(lock.try_lock());
  }
}

TEST_F(ConfigTests, test_config_update) {
  std::string digest;
  // Get a snapshot of the digest before making config updates.
  auto status = Config::getMD5(digest);
  EXPECT_TRUE(status);

  // Request an update of the 'new_source1'. Set new1 = value.
  status =
      Config::update({{"new_source1", "{\"options\": {\"new1\": \"value\"}}"}});
  EXPECT_TRUE(status);

  // At least, the amalgamated config digest should have changed.
  std::string new_digest;
  Config::getMD5(new_digest);
  EXPECT_NE(digest, new_digest);

  // Access the option that was added in the update to source 'new_source1'.
  {
    ConfigDataInstance config;
    auto option = config.data().get<std::string>("options.new1", "");
    EXPECT_EQ(option, "value");
  }

  // Add a lexically larger source that emits the same option 'new1'.
  Config::update({{"new_source2", "{\"options\": {\"new1\": \"changed\"}}"}});

  {
    ConfigDataInstance config;
    auto option = config.data().get<std::string>("options.new1", "");
    // Expect the amalgamation to have overwritten 'new_source1'.
    EXPECT_EQ(option, "changed");
  }

  // Again add a source but emit a different option, both 'new1' and 'new2'
  // should be in the amalgamated/merged config.
  Config::update({{"new_source3", "{\"options\": {\"new2\": \"different\"}}"}});

  {
    ConfigDataInstance config;
    auto option = config.data().get<std::string>("options.new1", "");
    EXPECT_EQ(option, "changed");
    option = config.data().get<std::string>("options.new2", "");
    EXPECT_EQ(option, "different");
  }
}

TEST_F(ConfigTests, test_splay) {
  auto val1 = splayValue(100, 10);
  EXPECT_GE(val1, 90);
  EXPECT_LE(val1, 110);

  auto val2 = splayValue(100, 10);
  EXPECT_GE(val2, 90);
  EXPECT_LE(val2, 110);

  auto val3 = splayValue(10, 0);
  EXPECT_EQ(val3, 10);

  auto val4 = splayValue(100, 1);
  EXPECT_GE(val4, 99);
  EXPECT_LE(val4, 101);

  auto val5 = splayValue(1, 10);
  EXPECT_EQ(val5, 1);
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
