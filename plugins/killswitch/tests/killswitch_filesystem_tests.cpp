/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <gtest/gtest.h>

#include <osquery/config/tests/test_utils.h>
#include <osquery/flags.h>
#include <osquery/registry.h>
#include <osquery/system.h>

#include "osquery/killswitch/plugins/killswitch_filesystem.h"

namespace osquery {

DECLARE_uint32(killswitch_refresh_rate);

class KillswitchFilesystemTests : public testing::Test {
public:
  void SetUp() override {
    Initializer::platformSetup();
    registryAndPluginInit();
  }
};

TEST_F(KillswitchFilesystemTests, test_killswitch_filesystem_plugin_legit) {
  KillswitchFilesystem plugin(getTestConfigDirectory() / "test_killswitch.conf");
  EXPECT_TRUE(plugin.refresh());
  {
    auto result = plugin.isEnabled("testSwitch");
    ASSERT_TRUE(result);
    ASSERT_TRUE(*result);
  }
  {
    auto result = plugin.isEnabled("test2Switch");
    ASSERT_TRUE(result);
    ASSERT_FALSE(*result);
  }
}
TEST_F(KillswitchFilesystemTests,
       test_killswitch_filesystem_plugin_incorrect_key) {
  KillswitchFilesystem plugin(getTestConfigDirectory() /
                              "test_killswitch_incorrect_key.conf");
  EXPECT_FALSE(plugin.refresh());
}
TEST_F(KillswitchFilesystemTests,
       test_killswitch_filesystem_plugin_incorrect_value) {
  KillswitchFilesystem plugin(getTestConfigDirectory() /
                              "test_killswitch_incorrect_value.conf");
  EXPECT_FALSE(plugin.refresh());
}
TEST_F(KillswitchFilesystemTests,
       test_killswitch_filesystem_plugin_incorrect_no_table) {
  KillswitchFilesystem plugin(getTestConfigDirectory() /
                              "test_killswitch_incorrect_value.conf");
  EXPECT_FALSE(plugin.refresh());
}
} // namespace osquery
