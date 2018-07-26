/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <osquery/flags.h>

#include "osquery/killswitch/plugins/killswitch_filesystem.h"
#include "osquery/tests/test_util.h"

namespace osquery {

DECLARE_uint32(killswitch_refresh_rate);

class KillswitchFilesystemTests : public testing::Test {};

TEST_F(KillswitchFilesystemTests, test_killswitch_filesystem_plugin) {
  KillswitchFilesystem plugin(kTestDataPath + "test_killswitch.conf");
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

} // namespace osquery
