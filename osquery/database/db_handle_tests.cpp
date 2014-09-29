// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/database/db_handle.h"

#include <algorithm>

#include <boost/filesystem/operations.hpp>

#include <glog/logging.h>
#include <gtest/gtest.h>

const std::string kDBHandleTestPath = "/tmp/rocksdb-osquery-dbhandletests";

namespace osquery {

class DBHandleTests : public testing::Test {
  void SetUp() {
    // Setup a testing DB instance
    auto& db = DBHandle::getInstanceAtPath(kDBHandleTestPath);
    cfh_queries = db.getHandleForColumnFamily(kQueries);
    cfh_foobar = db.getHandleForColumnFamily("foobartest");
  }

 public:
  rocksdb::ColumnFamilyHandle* cfh_queries;
  rocksdb::ColumnFamilyHandle* cfh_foobar;
};

TEST_F(DBHandleTests, test_create_new_database_on_disk) {
  auto& db = DBHandle::getInstance();
  EXPECT_TRUE(db.getStatus().ok());
  EXPECT_EQ(db.getStatus().toString(), "OK");
}

TEST_F(DBHandleTests, test_singleton_on_disk) {
  auto& db1 = DBHandle::getInstance();
  EXPECT_TRUE(db1.getStatus().ok());
  EXPECT_EQ(db1.getStatus().toString(), "OK");
  auto& db2 = DBHandle::getInstance();
  EXPECT_TRUE(db2.getStatus().ok());
  EXPECT_EQ(db2.getStatus().toString(), "OK");
}

TEST_F(DBHandleTests, test_get_handle_for_column_family) {
  ASSERT_TRUE(cfh_queries != nullptr);
  ASSERT_TRUE(cfh_foobar == nullptr);
}

TEST_F(DBHandleTests, test_get) {
  auto& db = DBHandle::getInstance();
  db.getDB()->Put(rocksdb::WriteOptions(), cfh_queries, "test_query_123", "{}");
  std::string r;
  std::string key = "test_query_123";
  auto s = db.Get(kQueries, key, r);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(r, "{}");
}

TEST_F(DBHandleTests, test_put) {
  auto& db = DBHandle::getInstance();
  auto s = db.Put(kQueries, "test_put", "bar");
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
}

TEST_F(DBHandleTests, test_delete) {
  auto& db = DBHandle::getInstance();
  db.Put(kQueries, "test_delete", "baz");
  auto s = db.Delete(kQueries, "test_delete");
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
}

TEST_F(DBHandleTests, test_scan) {
  auto& db = DBHandle::getInstance();
  db.Put(kQueries, "test_scan_foo1", "baz");
  db.Put(kQueries, "test_scan_foo2", "baz");
  db.Put(kQueries, "test_scan_foo3", "baz");
  std::vector<std::string> keys;
  std::vector<std::string> expected = {"test_scan_foo1", "test_scan_foo2",
                                       "test_scan_foo3"};
  auto s = db.Scan(kQueries, keys);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  for (const auto& i : expected) {
    EXPECT_NE(std::find(keys.begin(), keys.end(), i), keys.end());
  }
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  int status = RUN_ALL_TESTS();
  boost::filesystem::remove_all(kDBHandleTestPath);

  return status;
}
