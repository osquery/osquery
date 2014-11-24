// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/database/db_handle.h"

#include <algorithm>

#include <boost/filesystem/operations.hpp>

#include <glog/logging.h>
#include <gtest/gtest.h>

using osquery::Status;

const std::string kTestingDBHandlePath = "/tmp/rocksdb-osquery-dbhandletests";

namespace osquery {

class DBHandleTests : public testing::Test {
 public:
  void SetUp() {
    // Setup a testing DB instance
    db = DBHandle::getInstanceAtPath(kTestingDBHandlePath);
    cfh_queries = DBHandle::getInstance()->getHandleForColumnFamily(kQueries);
    cfh_foobar =
        DBHandle::getInstance()->getHandleForColumnFamily("foobartest");
  }

 public:
  rocksdb::ColumnFamilyHandle* cfh_queries;
  rocksdb::ColumnFamilyHandle* cfh_foobar;
  std::shared_ptr<DBHandle> db;
};

TEST_F(DBHandleTests, test_singleton_on_disk) {
  auto db1 = DBHandle::getInstance();
  auto db2 = DBHandle::getInstance();
  EXPECT_EQ(db1, db2);
}

TEST_F(DBHandleTests, test_get_handle_for_column_family) {
  ASSERT_TRUE(cfh_queries != nullptr);
  ASSERT_TRUE(cfh_foobar == nullptr);
}

TEST_F(DBHandleTests, test_get) {
  db->getDB()->Put(
      rocksdb::WriteOptions(), cfh_queries, "test_query_123", "{}");
  std::string r;
  std::string key = "test_query_123";
  auto s = db->Get(kQueries, key, r);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(r, "{}");
}

TEST_F(DBHandleTests, test_put) {
  auto s = db->Put(kQueries, "test_put", "bar");
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
}

TEST_F(DBHandleTests, test_delete) {
  db->Put(kQueries, "test_delete", "baz");
  auto s = db->Delete(kQueries, "test_delete");
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
}

TEST_F(DBHandleTests, test_scan) {
  db->Put(kQueries, "test_scan_foo1", "baz");
  db->Put(kQueries, "test_scan_foo2", "baz");
  db->Put(kQueries, "test_scan_foo3", "baz");
  std::vector<std::string> keys;
  std::vector<std::string> expected = {
      "test_scan_foo1", "test_scan_foo2", "test_scan_foo3"};
  auto s = db->Scan(kQueries, keys);
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
  boost::filesystem::remove_all(kTestingDBHandlePath);
  return status;
}
