/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <future>

#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/registry_factory.h>

#include "osquery/database/tests/plugin_tests.h"

namespace osquery {

DECLARE_string(database_path);

class EphemeralDatabasePluginTests : public DatabasePluginTests {
 protected:
  std::string name() override {
    return "ephemeral";
  }
};

// Define the default set of database plugin operation tests.
CREATE_DATABASE_TESTS(EphemeralDatabasePluginTests);

void DatabasePluginTests::SetUp() {
  auto& rf = RegistryFactory::get();
  existing_plugin_ = rf.getActive("database");
  rf.plugin("database", existing_plugin_)->tearDown();

  setName(name());
  path_ = FLAGS_database_path;
  removePath(path_);

  auto plugin = rf.plugin("database", getName());
  plugin_ = std::dynamic_pointer_cast<DatabasePlugin>(plugin);
  plugin_->reset();

  rf.setActive("database", getName());
}

void DatabasePluginTests::TearDown() {
  auto& rf = RegistryFactory::get();
  rf.plugin("database", name_)->tearDown();
  rf.setActive("database", existing_plugin_);
}

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

auto kTestReseter = ([]() { resetDatabase(); });

void DatabasePluginTests::testReset() {
  RegistryFactory::get().setActive("database", getName());
  setDatabaseValue(kLogs, "reset", "1");
  resetDatabase();

  if ("ephemeral" != getName()) {
    // The ephemeral plugin is special and does not persist after reset.
    std::string value;
    EXPECT_TRUE(getDatabaseValue(kLogs, "reset", value));
    EXPECT_EQ(value, "1");
  }
}

void DatabasePluginTests::testPut() {
  auto s = getPlugin()->put(kQueries, "test_put", "bar");
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.getMessage(), "OK");

  s = setDatabaseValue(kQueries, "test_put", "");
  EXPECT_TRUE(s.ok());

  PluginRequest req = {{"action", "put"},
                       {"domain", kQueries},
                       {"key", "test_put"},
                       {"value", "bar"}};
  s = Registry::call("database", getName(), req);
  EXPECT_TRUE(s.ok());

  auto reset = std::async(std::launch::async, kTestReseter);
  reset.get();
}

void DatabasePluginTests::testGet() {
  getPlugin()->put(kQueries, "test_get", "bar");

  std::string r;
  auto s = getPlugin()->get(kQueries, "test_get", r);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.getMessage(), "OK");
  EXPECT_EQ(r, "bar");

  auto reset = std::async(std::launch::async, kTestReseter);
  reset.get();
}

void DatabasePluginTests::testDelete() {
  getPlugin()->put(kQueries, "test_delete", "baz");
  auto s = getPlugin()->remove(kQueries, "test_delete");
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.getMessage(), "OK");
}

void DatabasePluginTests::testDeleteRange() {
  getPlugin()->put(kQueries, "test_delete", "baz");
  getPlugin()->put(kQueries, "test1", "1");
  getPlugin()->put(kQueries, "test2", "2");
  getPlugin()->put(kQueries, "test3", "3");
  getPlugin()->put(kQueries, "test4", "4");
  auto s = getPlugin()->removeRange(kQueries, "test1", "test3");
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.getMessage(), "OK");

  std::string r;
  getPlugin()->get(kQueries, "test4", r);
  EXPECT_EQ(r, "4");
  getPlugin()->get(kQueries, "test_delete", r);
  EXPECT_EQ(r, "baz");
  s = getPlugin()->get(kQueries, "test1", r);
  EXPECT_FALSE(s.ok());
  s = getPlugin()->get(kQueries, "test2", r);
  EXPECT_FALSE(s.ok());
  s = getPlugin()->get(kQueries, "test3", r);
  EXPECT_FALSE(s.ok());

  // Expect invalid logically ranges to have no effect.
  getPlugin()->put(kQueries, "new_test1", "1");
  getPlugin()->put(kQueries, "new_test2", "2");
  getPlugin()->put(kQueries, "new_test3", "3");
  getPlugin()->put(kQueries, "new_test4", "4");
  s = getPlugin()->removeRange(kQueries, "new_test3", "new_test2");
  EXPECT_TRUE(s.ok());
  getPlugin()->get(kQueries, "new_test2", r);
  EXPECT_EQ(r, "2");
  getPlugin()->get(kQueries, "new_test3", r);
  EXPECT_EQ(r, "3");

  // An equality range will not delete that single item.
  s = getPlugin()->removeRange(kQueries, "new_test2", "new_test2");
  EXPECT_TRUE(s.ok());
  s = getPlugin()->get(kQueries, "new_test2", r);
  EXPECT_FALSE(s.ok());
}

void DatabasePluginTests::testScan() {
  getPlugin()->put(kQueries, "test_scan_foo1", "baz");
  getPlugin()->put(kQueries, "test_scan_foo2", "baz");
  getPlugin()->put(kQueries, "test_scan_foo3", "baz");

  std::vector<std::string> keys;
  std::vector<std::string> expected = {
      "test_scan_foo1", "test_scan_foo2", "test_scan_foo3"};
  auto s = getPlugin()->scan(kQueries, keys, "", 0);
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
