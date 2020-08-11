/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <gtest/gtest.h>

#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

class SyslogLoggerTests : public testing::Test {
protected:
 void SetUp() {
   platformSetup();
   registryAndPluginInit();
 }
};

TEST_F(SyslogLoggerTests, test_syslog) {
  auto active = Registry::get().getActive("logger");
  EXPECT_TRUE(Registry::get().exists("logger", "syslog"));

  EXPECT_TRUE(Registry::get().setActive("logger", "syslog"));
  EXPECT_TRUE(Registry::get().plugin("logger", "syslog")->setUp());
  Registry::get().setActive("logger", active);
}
}
