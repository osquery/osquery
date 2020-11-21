/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <future>

#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/database/tests/test_utils.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/registry/registry.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/json/json.h>

#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

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
  platformSetup();
  registryAndPluginInit();
  initDatabasePluginForTesting();

  auto& rf = RegistryFactory::get();
  existing_plugin_ = rf.getActive("database");
  rf.plugin("database", existing_plugin_)->tearDown();

  setName(name());
  previous_path_ = FLAGS_database_path;
  FLAGS_database_path =
      (fs::temp_directory_path() /
       fs::unique_path("osquery.database_plugin_tests.%%%%.%%%%.%%%%.%%%%.db"))
          .string();
  path_ = FLAGS_database_path;
  // removePath(path_);

  auto plugin = rf.plugin("database", getName());
  plugin_ = std::dynamic_pointer_cast<DatabasePlugin>(plugin);
  plugin_->reset();

  rf.setActive("database", getName());
}

void DatabasePluginTests::TearDown() {
  auto& rf = RegistryFactory::get();
  rf.plugin("database", name_)->tearDown();
  rf.setActive("database", existing_plugin_);
  fs::remove_all(fs::path(path_));
  FLAGS_database_path = previous_path_;
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

void DatabasePluginTests::testPutBatch() {
  DatabaseStringValueList string_batch = {
      {"test_put_str1", "test_put_str1_value"},
      {"test_put_str2", "test_put_str2_value"}};

  auto s = getPlugin()->putBatch(kQueries, string_batch);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.getMessage(), "OK");

  for (const auto& p : string_batch) {
    const auto& key = p.first;
    const auto& expected_value = p.second;

    std::string value;
    s = getDatabaseValue(kQueries, key, value);
    EXPECT_EQ(s.getMessage(), "OK");

    EXPECT_EQ(expected_value, value);
  }

  DatabaseStringValueList str_batch2 = {
      {"test_plugin_put_json_str1", "test_put_str1_value"},
      {"test_plugin_put_json_str2", "test_put_str2_value"}};

  auto json_object = JSON::newObject();
  for (const auto& p : str_batch2) {
    const auto& key = p.first;
    const auto& value = p.second;

    json_object.addRef(key, value);
  }

  std::string serialized_data;
  s = json_object.toString(serialized_data);
  EXPECT_TRUE(s.ok());

  PluginRequest request = {
      {"action", "putBatch"}, {"domain", kQueries}, {"json", serialized_data}};

  s = Registry::call("database", getName(), request);
  EXPECT_TRUE(s.ok());

  for (const auto& p : str_batch2) {
    const auto& key = p.first;
    const auto& expected_value = p.second;

    std::string value;
    s = getDatabaseValue(kQueries, key, value);
    EXPECT_EQ(s.getMessage(), "OK");

    EXPECT_EQ(expected_value, value);
  }

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

  std::string r;
  s = getPlugin()->get(kQueries, "test_delete", r);
  EXPECT_FALSE(s.ok());
  EXPECT_TRUE(r.empty());
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
  EXPECT_FALSE(s.ok());
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
} // namespace osquery
