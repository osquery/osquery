/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <cstdint>
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
#include "osquery/killswitch/plugins/killswitch_json.h"
#include "osquery/tests/test_util.h"

namespace osquery {

DECLARE_uint32(killswitch_refresh_rate);

class KillswitchJSONTests : public testing::Test {
 protected:
  void SetUp() {
    refresh_ = FLAGS_killswitch_refresh_rate;
    FLAGS_killswitch_refresh_rate = 0;
  }

  void TearDown() {
    FLAGS_killswitch_refresh_rate = refresh_;
  }

 private:
  uint32_t refresh_{0};
};

class KillswitchJSONTestHelper : public KillswitchJSON {
 public:
  std::atomic<int> refresh_{0};
  std::atomic<int> get_{0};
  std::atomic<int> get_error_{0};

  void set(Status status, std::string content) {
    content_ = content;
    status_ = status;
  }

 protected:
  Status getJSON(std::string& content) override {
    get_++;
    if (status_.ok()) {
      content = content_;
    } else {
      get_error_++;
    }
    return status_;
  }

 private:
  std::string content_;
  Status status_;
};

TEST_F(KillswitchJSONTests, test_killswitch_JSON_plugin_set) {
  auto& rf = RegistryFactory::get();
  auto plugin = std::make_shared<KillswitchJSONTestHelper>();

  rf.registry("killswitch")->add("test", plugin);
  EXPECT_TRUE(rf.setActive("killswitch", "test").ok());
  RegistryFactory::get().registry("killswitch")->remove("test");
}

TEST_F(KillswitchJSONTests, test_killswitch_JSON_plugin_initial_values) {
  auto& rf = RegistryFactory::get();
  auto plugin = std::make_shared<KillswitchJSONTestHelper>();

  rf.registry("killswitch")->add("test", plugin);
  rf.setActive("killswitch", "test");

  auto result = Killswitch::get().isSwitchOn("testSwitch");
  EXPECT_FALSE(result);

  result = Killswitch::get().isSwitchOn("test2Switch");
  EXPECT_FALSE(result);
  RegistryFactory::get().registry("killswitch")->remove("test");
}

TEST_F(KillswitchJSONTests, test_killswitch_JSON_plugin_switch_valid) {
  auto& rf = RegistryFactory::get();
  auto plugin = std::make_shared<KillswitchJSONTestHelper>();

  rf.registry("killswitch")->add("test", plugin);
  rf.setActive("killswitch", "test");
  plugin->set(Status(), "{ \"testSwitch\":true, \"test2Switch\":false }");
  EXPECT_TRUE(Killswitch::get().refresh().ok());
  EXPECT_EQ(plugin->get_, 1);
  EXPECT_EQ(plugin->get_error_, 0);

  auto result = Killswitch::get().isSwitchOn("testSwitch");
  EXPECT_TRUE(result);
  EXPECT_TRUE(*result);

  result = Killswitch::get().isSwitchOn("test2Switch");
  EXPECT_TRUE(result);
  EXPECT_FALSE(*result);
  RegistryFactory::get().registry("killswitch")->remove("test");
}
} // namespace osquery
