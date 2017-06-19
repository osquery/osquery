/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/logger.h>

#include "osquery/tests/test_additional_util.h"
#include "osquery/tests/test_util.h"

namespace osquery {

class SyslogLoggerTests : public testing::Test {};

TEST_F(SyslogLoggerTests, test_syslog) {
  auto active = Registry::get().getActive("logger");
  EXPECT_TRUE(Registry::get().exists("logger", "syslog"));

  EXPECT_TRUE(Registry::get().setActive("logger", "syslog"));
  EXPECT_TRUE(Registry::get().plugin("logger", "syslog")->setUp());
  Registry::get().setActive("logger", active);
}
}
