/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/killswitch.h>
#include <osquery/packs.h>
#include <osquery/registry.h>
#include <osquery/sql.h>

#include "osquery/core/json.h"
#include "osquery/core/process.h"
#include "osquery/killswitch.h"
#include "osquery/killswitch/killswitch_plugin.h"
#include "osquery/killswitch/plugins/killswitch_filesystem.h"
#include "osquery/tests/test_util.h"

namespace osquery {

DECLARE_uint32(killswitch_refresh_rate);

class KillswitchTests : public testing::Test {};

TEST_F(KillswitchTests, test_killswitch_plugin) {
  auto& rf = RegistryFactory::get();
  auto plugin = std::make_shared<KillswitchPlugin>();
  rf.registry("killswitch")->add("test", plugin);
  EXPECT_TRUE(rf.setActive("killswitch", "test").ok());

  {
    PluginResponse response;
    auto status =
        Registry::call("killswitch",
                       {{"action", "isEnabled"}, {"key", "testSwitch"}},
                       response);
    EXPECT_FALSE(status.ok());
  }

  {
    PluginResponse response;
    auto status =
        Registry::call("killswitch", {{"key", "testSwitch"}}, response);
    EXPECT_FALSE(status.ok());
  }

  {
    PluginResponse response;
    auto status =
        Registry::call("killswitch", {{"action", "testSwitch"}}, response);
    EXPECT_FALSE(status.ok());
  }

  plugin->addCacheEntry("testSwitch", true);

  {
    auto result = plugin->isEnabled("testSwitch");
    EXPECT_TRUE(result);
    EXPECT_TRUE(*result);
  }
  {
    PluginResponse response;
    auto status =
        Registry::call("killswitch",
                       {{"action", "isEnabled"}, {"key", "testSwitch"}},
                       response);
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(response[0]["isEnabled"], std::string("true"));
    auto result = Killswitch::get().isSwitchOn("testSwitch");
    EXPECT_TRUE(result);
    EXPECT_TRUE(*result);
  }

  plugin->addCacheEntry("testSwitch", false);

  {
    auto result = plugin->isEnabled("testSwitch");
    EXPECT_TRUE(result);
    EXPECT_FALSE(*result);
  }
  {
    PluginResponse response;
    auto status =
        Registry::call("killswitch",
                       {{"action", "isEnabled"}, {"key", "testSwitch"}},
                       response);
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(response[0]["isEnabled"], std::string("false"));
    auto result = Killswitch::get().isSwitchOn("testSwitch");
    EXPECT_TRUE(result);
    EXPECT_FALSE(*result);
  }

  plugin->clearCache();

  {
    PluginResponse response;
    auto status =
        Registry::call("killswitch",
                       {{"action", "isEnabled"}, {"key", "testSwitch"}},
                       response);
    EXPECT_FALSE(status.ok());
    EXPECT_EQ(response.size(), 0);
    auto result = Killswitch::get().isSwitchOn("testSwitch");
    EXPECT_FALSE(result);
  }

  EXPECT_FALSE(Killswitch::get().refresh().ok());

  rf.registry("killswitch")->remove("test");
}

} // namespace osquery
