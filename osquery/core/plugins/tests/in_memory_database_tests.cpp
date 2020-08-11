/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/core/database/in_memory_database.h>
#include <osquery/database/database.h>

namespace osquery {

GTEST_TEST(InMemoryDatabaseTest, test_open) {
  auto db = std::make_unique<InMemoryDatabase>("test");
  auto result = db->open();
  EXPECT_TRUE(result);
  db->close();
}

GTEST_TEST(InMemoryDatabaseTest, test_destroy) {
  auto db = std::make_unique<InMemoryDatabase>("test");
  ASSERT_FALSE(db->open().isError());
  ASSERT_FALSE(db->putInt32(kPersistentSettings, "key", 10).isError());
  db->close();
  // In memory db should be destroyed on close
  // but we want to test that destroy is not failing for no reason
  auto result = db->destroyDB();
  EXPECT_TRUE(result);
  ASSERT_FALSE(db->open().isError());
  auto get_result = db->getInt32(kPersistentSettings, "key");
  EXPECT_FALSE(get_result);
  EXPECT_EQ(get_result.getError(), DatabaseError::KeyNotFound);
}

GTEST_TEST(InMemoryDatabaseTest, test_put) {
  auto db = std::make_unique<InMemoryDatabase>("test");
#ifdef NDEBUG
  auto result = db->putInt32("test", "test", 23);
  EXPECT_FALSE(result);
  EXPECT_EQ(result.getError(), DatabaseError::DbIsNotOpen);
#endif
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

GTEST_TEST(InMemoryDatabaseTest, test_domain_error) {
  auto db = std::make_unique<InMemoryDatabase>("test");
  ASSERT_FALSE(db->open().isError());
  auto result = db->putInt32("bad_domain", "key", 12);
  EXPECT_FALSE(result);
  EXPECT_EQ(result.takeError(), DatabaseError::DomainNotFound);
}

GTEST_TEST(InMemoryDatabaseTest, test_unknown_key) {
  auto db = std::make_unique<InMemoryDatabase>("test");
  ASSERT_FALSE(db->open().isError());
  ASSERT_FALSE(db->putInt32(kPersistentSettings, "key", 12).isError());
  auto result = db->getInt32(kPersistentSettings, "key_");
  EXPECT_FALSE(result);
  EXPECT_EQ(result.takeError(), DatabaseError::KeyNotFound);
}

GTEST_TEST(InMemoryDatabaseTest, test_keys_search) {
  auto db = std::make_unique<InMemoryDatabase>("test");
  ASSERT_FALSE(db->open().isError());
  ASSERT_FALSE(db->putInt32(kPersistentSettings, "key_1", 1).isError());
  ASSERT_FALSE(db->putInt32(kPersistentSettings, "key_2", 2).isError());
  ASSERT_FALSE(db->putInt32(kPersistentSettings, "key_3", 3).isError());
  ASSERT_FALSE(db->putInt32(kPersistentSettings, "kEy_1", 4).isError());
  ASSERT_FALSE(db->putInt32(kPersistentSettings, "kEy_2", 5).isError());
  auto result_all = db->getKeys(kPersistentSettings);
  EXPECT_TRUE(result_all);
  EXPECT_EQ((*result_all).size(), 5);
  auto result_some = db->getKeys(kPersistentSettings, "key");
  EXPECT_TRUE(result_some);
  EXPECT_EQ((*result_some).size(), 3);
}

} // namespace osquery
