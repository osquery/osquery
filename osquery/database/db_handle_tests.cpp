// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/database/db_handle.h"

#include <algorithm>

#include <glog/logging.h>
#include <gtest/gtest.h>

using osquery::Status;

namespace osquery {
namespace db {

class DBHandleTests : public testing::Test {};

TEST_F(DBHandleTests, test_create_new_database_on_disk) {
  auto db = DBHandle::getInstanceAtPath("/tmp/rocksdb-osquery-test1");
  EXPECT_TRUE(db->getStatus().ok());
  EXPECT_EQ(db->getStatus().toString(), "OK");
}

TEST_F(DBHandleTests, test_singleton_on_disk) {
  auto db1 = DBHandle::getInstanceAtPath("/tmp/rocksdb-osquery-test2");
  EXPECT_TRUE(db1->getStatus().ok());
  EXPECT_EQ(db1->getStatus().toString(), "OK");
  auto db2 = DBHandle::getInstanceAtPath("/tmp/rocksdb-osquery-test3");
  EXPECT_TRUE(db2->getStatus().ok());
  EXPECT_EQ(db2->getStatus().toString(), "OK");
  EXPECT_EQ(db1, db2);
}

TEST_F(DBHandleTests, test_get_handle_for_column_family) {
  auto db = DBHandle::getInstanceAtPath("/tmp/rocksdb-osquery-test4");
  auto cfh1 = db->getHandleForColumnFamily(kQueries);
  ASSERT_TRUE(cfh1 != nullptr);
  auto cfh2 = db->getHandleForColumnFamily("foobartest");
  ASSERT_TRUE(cfh2 == nullptr);
}

TEST_F(DBHandleTests, test_get) {
  auto db = DBHandle::getInstanceAtPath("/tmp/rocksdb-osquery-test5");
  db->getDB()->Put(rocksdb::WriteOptions(),
                   db->getHandleForColumnFamily(kQueries),
                   "test_query_123",
                   "{}");
  std::string r;
  std::string key = "test_query_123";
  auto s = db->Get(kQueries, key, r);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(r, "{}");
}

TEST_F(DBHandleTests, test_put) {
  auto db = DBHandle::getInstanceAtPath("/tmp/rocksdb-osquery-test6");
  auto s = db->Put(kQueries, "test_put", "bar");
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
}

TEST_F(DBHandleTests, test_delete) {
  auto db = DBHandle::getInstanceAtPath("/tmp/rocksdb-osquery-test7");
  db->Put(kQueries, "test_delete", "baz");
  auto s = db->Delete(kQueries, "test_delete");
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
}

TEST_F(DBHandleTests, test_scan) {
  auto db = DBHandle::getInstanceAtPath("/tmp/rocksdb-osquery-test8");
  db->Put(kQueries, "test_scan_foo1", "baz");
  db->Put(kQueries, "test_scan_foo2", "baz");
  db->Put(kQueries, "test_scan_foo3", "baz");
  std::vector<std::string> keys;
  std::vector<std::string> expected = {"test_scan_foo1", "test_scan_foo2",
                                       "test_scan_foo3"};
  auto s = db->Scan(kQueries, keys);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  for (const auto& i : expected) {
    EXPECT_NE(std::find(keys.begin(), keys.end(), i), keys.end());
  }
}
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
