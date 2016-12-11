/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/database/tests/plugin_tests.h"

namespace osquery {

class EphemeralDatabasePluginTests : public DatabasePluginTests {
 protected:
  std::string name() override {
    return "ephemeral";
  }
};

// Define the default set of database plugin operation tests.
CREATE_DATABASE_TESTS(EphemeralDatabasePluginTests);

void DatabasePluginTests::testPluginCheck() {
  auto& rf = RegistryFactory::get();

  // Do not worry about multiple set-active calls.
  // For testing purposes they should be idempotent.
  EXPECT_TRUE(rf.setActive("database", getName()));

  // Get an instance of the database plugin and call check.
  auto plugin = rf.plugin("database", getName());
  auto db_plugin = std::dynamic_pointer_cast<DatabasePlugin>(plugin);
  EXPECT_TRUE(db_plugin->checkDB());

  // Testing relies on database resetting too.
  EXPECT_TRUE(db_plugin->reset());
}

void DatabasePluginTests::testPut() {
  auto s = getPlugin()->put(kQueries, "test_put", "bar");
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.getMessage(), "OK");
}

void DatabasePluginTests::testGet() {
  getPlugin()->put(kQueries, "test_get", "bar");

  std::string r;
  auto s = getPlugin()->get(kQueries, "test_get", r);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.getMessage(), "OK");
  EXPECT_EQ(r, "bar");
}

void DatabasePluginTests::testDelete() {
  getPlugin()->put(kQueries, "test_delete", "baz");
  auto s = getPlugin()->remove(kQueries, "test_delete");
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.getMessage(), "OK");
}

void DatabasePluginTests::testScan() {
  getPlugin()->put(kQueries, "test_scan_foo1", "baz");
  getPlugin()->put(kQueries, "test_scan_foo2", "baz");
  getPlugin()->put(kQueries, "test_scan_foo3", "baz");

  std::vector<std::string> keys;
  std::vector<std::string> expected = {
      "test_scan_foo1", "test_scan_foo2", "test_scan_foo3"};
  auto s = getPlugin()->scan(kQueries, keys, "");
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.getMessage(), "OK");
  EXPECT_EQ(keys.size(), 3U);
  for (const auto& i : expected) {
    EXPECT_NE(std::find(keys.begin(), keys.end(), i), keys.end());
  }
}

void DatabasePluginTests::testScanLimit() {
  getPlugin()->put(kQueries, "test_scan_foo1", "baz");
  getPlugin()->put(kQueries, "test_scan_foo2", "baz");
  getPlugin()->put(kQueries, "test_scan_foo3", "baz");

  std::vector<std::string> keys;
  auto s = getPlugin()->scan(kQueries, keys, "", 2);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.getMessage(), "OK");
  EXPECT_EQ(keys.size(), 2U);
}
}
