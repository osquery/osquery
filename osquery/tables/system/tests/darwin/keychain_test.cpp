/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/tables/system/darwin/keychain.h>

namespace fs = boost::filesystem;

namespace osquery::tables {

class KeychainTest : public testing::Test {
 protected:
  fs::path test_working_dir_;

  void SetUp() override {
    test_working_dir_ = fs::temp_directory_path() /
                        fs::unique_path("osquery.test_working_dir.%%%%.%%%%");
    fs::create_directories(test_working_dir_);
  }

  void TearDown() override {
    fs::remove_all(test_working_dir_);
  }
};

TEST_F(KeychainTest, keychain_cache) {
  EXPECT_EQ(keychainCache.Size(), 0);

  KeychainTable table = KeychainTable::CERTIFICATES;
  std::string hash;
  QueryData results;

  // Create a file and check cache.
  boost::filesystem::path path = test_working_dir_ / "cache.keychain";
  boost::filesystem::save_string_file(path, "contents");
  bool err;
  EXPECT_FALSE(keychainCache.Read(path, table, hash, results, err));
  EXPECT_FALSE(err);
  EXPECT_EQ(keychainCache.Size(), 0);

  // Write to cache
  {
    QueryData new_results;
    Row row;
    row["foo"] = "bar";
    new_results.push_back(row);
    keychainCache.Write(path, table, hash, new_results);
    EXPECT_EQ(keychainCache.Size(), 1);
  }

  // Read results.
  {
    QueryData new_results;
    hash = "";
    EXPECT_TRUE(keychainCache.Read(path, table, hash, new_results, err));
    EXPECT_FALSE(err);
    EXPECT_EQ(new_results.size(), 1);
    EXPECT_EQ(new_results[0]["foo"], "bar");
  }

  // Overwrite cache results.
  {
    QueryData new_results;
    Row row;
    row["key"] = "value";
    new_results.push_back(row);
    keychainCache.Write(path, table, hash, new_results);
    EXPECT_EQ(keychainCache.Size(), 1);
    // Write results to another path for good measure
    new_results.emplace_back();
    keychainCache.Write("bozo", table, hash, new_results);
    EXPECT_EQ(keychainCache.Size(), 2);
  }

  // Read access throttled. Cached result returned.
  boost::filesystem::save_string_file(path, "contents_modified");
  FLAGS_keychain_access_interval = 1;
  {
    QueryData new_results;
    hash = "";
    EXPECT_TRUE(keychainCache.Read(path, table, hash, new_results, err));
    EXPECT_FALSE(err);
    EXPECT_EQ(new_results.size(), 1);
    EXPECT_EQ(new_results[0]["key"], "value");
  }

  // Read access NOT throttled. Cache miss.
  FLAGS_keychain_access_interval = 0;
  {
    QueryData new_results;
    hash = "";
    EXPECT_FALSE(keychainCache.Read(path, table, hash, new_results, err));
    EXPECT_FALSE(err);
    EXPECT_EQ(new_results.size(), 0);
  }

}

TEST_F(KeychainTest, keychain_cache_bad_path) {
  boost::filesystem::path path = test_working_dir_ / "does_not_exist";
  KeychainTable table = KeychainTable::KEYCHAIN_ITEMS;
  std::string hash;
  QueryData results;
  bool err;
  EXPECT_FALSE(keychainCache.Read(path, table, hash, results, err));
  EXPECT_TRUE(err);
  EXPECT_EQ(results.size(), 0);
}

}