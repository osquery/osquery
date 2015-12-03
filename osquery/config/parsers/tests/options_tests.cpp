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

#include <osquery/config.h>
#include <osquery/registry.h>

#include "osquery/core/test_util.h"

namespace osquery {

class OptionsConfigParserPluginTests : public testing::Test {};

TEST_F(OptionsConfigParserPluginTests, test_get_option) {
  Config c;
  auto s = c.update(getTestConfigMap());
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  EXPECT_EQ(c.getParser("options")->getData().get_child("options").get<bool>(
                "enable_monitor"),
            true);
}
}
