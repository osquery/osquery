/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/registry/registry.h>
#include <osquery/utils/status/status.h>

namespace osquery {

class UUIDTests : public testing::Test {};

TEST_F(UUIDTests, test_invalid_uuid) {
  std::string uuid = "10000000-0000-8000-0040-000000000000";

  EXPECT_TRUE(isPlaceholderHardwareUUID(uuid));
}

TEST_F(UUIDTests, test_valid_uuid) {
  std::string uuid = "226e380e-67d1-4214-9868-5383a79af0b8";

  EXPECT_FALSE(isPlaceholderHardwareUUID(uuid));
}

class UUIDDatabaseTests : public testing::Test {
 protected:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
  }
};

TEST_F(UUIDDatabaseTests, test_host_uuid_stable_across_database_reset) {
  std::string before;
  ASSERT_TRUE(getHostUUID(before).ok());
  ASSERT_FALSE(before.empty());

  // The scheduler periodically resets the database (--schedule_reload), which
  // empties the ephemeral database used with --disable_database.
  resetDatabase();

  std::string after;
  ASSERT_TRUE(getHostUUID(after).ok());
  EXPECT_EQ(before, after);
}

TEST_F(UUIDDatabaseTests, test_instance_uuid_stable_across_database_reset) {
  std::string before;
  ASSERT_TRUE(getInstanceUUID(before).ok());
  ASSERT_FALSE(before.empty());

  resetDatabase();

  std::string after;
  ASSERT_TRUE(getInstanceUUID(after).ok());
  EXPECT_EQ(before, after);
}

} // namespace osquery
