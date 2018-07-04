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
#include "osquery/killswitch/killswitch_plugin.h"
#include "osquery/killswitch/plugins/killswitch_filesystem.h"
#include "osquery/tests/test_util.h"

namespace osquery {

DECLARE_uint32(killswitch_refresh_rate);
DECLARE_uint32(x);
// DECLARE_string(killswitch_config_path);

class KillswitchTests : public testing::Test {
 protected:
  void SetUp() {
    refresh_ = FLAGS_killswitch_refresh_rate;
    FLAGS_killswitch_refresh_rate = 0;
    refresh_ = FLAGS_x;
    // config_path_ = FLAGS_killswitch_config_path;
    // FLAGS_killswitch_config_path = kTestDataPath + "test_killswitch.conf";

    createMockFileStructure();
  }

  void TearDown() {
    tearDownMockFileStructure();

    FLAGS_killswitch_refresh_rate = refresh_;
    // FLAGS_killswitch_config_path = config_path_;
  }

 protected:
  Killswitch& get() {
    return Killswitch::get();
  }

 private:
  std::string config_path_;
  size_t refresh_{0};
};

class TestKillswitchPlugin : public KillswitchFilesystem {
 public:
  std::atomic<int> refresh_count_{0};

 private:
  virtual Status refresh() override{
    refresh_count_++;
    return KillswitchFilesystem::refresh();
  }
};

TEST_F(KillswitchTests, test_plugin) {}

} // namespace osquery
