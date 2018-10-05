/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <osquery/core/database/rocksdb_database.h>
#include <osquery/database.h>

namespace osquery {

class RocksdbDatabaseTest : public ::testing::Test {
 protected:
  std::string path_;

  virtual void SetUp() {
    boost::uuids::uuid uuid = boost::uuids::random_generator()();
    auto random_name = boost::uuids::to_string(uuid);
    auto path = boost::filesystem::temp_directory_path().append(random_name);
    boost::filesystem::create_directory(path);
    path_ = path.string();
  }

  virtual void TearDown() {
    boost::filesystem::remove_all(path_);
  }
};

std::string randomDBPath() {
  boost::uuids::uuid uuid = boost::uuids::random_generator()();
  auto random_name = boost::uuids::to_string(uuid);
  auto path = boost::filesystem::temp_directory_path().append(random_name);
  boost::filesystem::create_directory(path);
  return path.string();
}

TEST_F(RocksdbDatabaseTest, test_open) {
  auto path = randomDBPath();
  auto db = std::make_unique<RocksdbDatabase>("test", path_);
  auto result = db->open();
  EXPECT_TRUE(result);
  db->close();
}

TEST_F(RocksdbDatabaseTest, test_destroy) {
  auto db = std::make_unique<RocksdbDatabase>("test", path_);
  ASSERT_TRUE(db->open());
  EXPECT_TRUE(db->putInt32(kPersistentSettings, "key", 10));
  db->close();
  auto result = db->destroyDB();
  EXPECT_TRUE(result);
  EXPECT_TRUE(db->open());
  auto get_result = db->getInt32(kPersistentSettings, "key");
  EXPECT_FALSE(get_result);
  EXPECT_EQ(get_result.getError(), DatabaseError::KeyNotFound);
}

TEST_F(RocksdbDatabaseTest, test_put) {
  auto db = std::make_unique<RocksdbDatabase>("test", path_);
  auto result = db->putInt32("test", "test", 23);
  EXPECT_FALSE(result);
  EXPECT_EQ(result.getError(), DatabaseError::DbIsNotOpen);
  EXPECT_TRUE(db->open());
  EXPECT_TRUE(db->putInt32(kPersistentSettings, "test_key_int", 12));
  auto int_value = db->getInt32(kPersistentSettings, "test_key_int");
  EXPECT_TRUE(int_value);
  EXPECT_EQ(int_value.take(), 12);

  EXPECT_TRUE(db->putString(kPersistentSettings, "test_key_string", "string"));
  auto string_value = db->getString(kPersistentSettings, "test_key_string");
  EXPECT_TRUE(string_value);
  EXPECT_EQ(string_value.take(), "string");
}

TEST_F(RocksdbDatabaseTest, test_domain_error) {
  auto db = std::make_unique<RocksdbDatabase>("test", path_);
  ASSERT_TRUE(db->open());
  auto result = db->putInt32("bad_domain", "key", 12);
  EXPECT_FALSE(result);
  EXPECT_EQ(result.takeError(), DatabaseError::DomainNotFound);
}

TEST_F(RocksdbDatabaseTest, test_unknown_key) {
  auto db = std::make_unique<RocksdbDatabase>("test", path_);
  ASSERT_TRUE(db->open());
  EXPECT_TRUE(db->putInt32(kPersistentSettings, "key", 12));
  auto result = db->getInt32(kPersistentSettings, "key_");
  EXPECT_FALSE(result);
  EXPECT_EQ(result.takeError(), DatabaseError::KeyNotFound);
}

TEST_F(RocksdbDatabaseTest, test_keys_search) {
  auto db = std::make_unique<RocksdbDatabase>("test", path_);
  ASSERT_TRUE(db->open());
  EXPECT_TRUE(db->putInt32(kPersistentSettings, "key_1", 1));
  EXPECT_TRUE(db->putInt32(kPersistentSettings, "key_2", 2));
  EXPECT_TRUE(db->putInt32(kPersistentSettings, "key_3", 3));
  EXPECT_TRUE(db->putInt32(kPersistentSettings, "kEy_1", 4));
  EXPECT_TRUE(db->putInt32(kPersistentSettings, "kEy_2", 5));
  auto result_all = db->getKeys(kPersistentSettings);
  EXPECT_TRUE(result_all);
  EXPECT_EQ((*result_all).size(), 5);
  auto result_some = db->getKeys(kPersistentSettings, "key");
  EXPECT_TRUE(result_some);
  EXPECT_EQ((*result_some).size(), 3);
}

} // namespace osquery
