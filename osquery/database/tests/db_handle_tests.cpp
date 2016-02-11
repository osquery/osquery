/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <algorithm>

#include <boost/filesystem/operations.hpp>

#include <gtest/gtest.h>

#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#include "osquery/database/db_handle.h"
#include "osquery/core/test_util.h"

namespace osquery {

class DBHandleTests : public testing::Test {
 public:
  void SetUp() {
    // A database instance is setup during testing initialize (initTesting).
    // We need to reset that instance to test unordered expectations.
    path_ = kTestWorkingDirectory + std::to_string(rand() % 10000 + 20000);
    DBHandle::getInstance()->resetInstance(path_, false);

    cfh_queries_ = DBHandle::getInstance()->getHandleForColumnFamily(kQueries);
    cfh_foobar_ =
        DBHandle::getInstance()->getHandleForColumnFamily("foobartest");
    db_ = DBHandle::getInstance();
  }

  void TearDown() {
    // Clean the transient instance and reset to the testing instance.
    boost::filesystem::remove_all(path_);
    auto path = Flag::getValue("database_path");
    DBHandle::getInstance()->resetInstance(path, false);
  }

 public:
  std::string path_;
  rocksdb::ColumnFamilyHandle* cfh_queries_;
  rocksdb::ColumnFamilyHandle* cfh_foobar_;
  std::shared_ptr<DBHandle> db_;
};

TEST_F(DBHandleTests, test_singleton_on_disk) {
  auto db1 = DBHandle::getInstance();
  auto db2 = DBHandle::getInstance();
  EXPECT_EQ(db1, db2);
}

TEST_F(DBHandleTests, test_get_handle_for_column_family) {
  ASSERT_TRUE(cfh_queries_ != nullptr);
  ASSERT_TRUE(cfh_foobar_ == nullptr);
}

TEST_F(DBHandleTests, test_get) {
  db_->getDB()->Put(
      rocksdb::WriteOptions(), cfh_queries_, "test_query_123", "{}");
  std::string r;
  std::string key = "test_query_123";
  auto s = db_->Get(kQueries, key, r);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(r, "{}");
}

TEST_F(DBHandleTests, test_put) {
  auto s = db_->Put(kQueries, "test_put", "bar");
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
}

TEST_F(DBHandleTests, test_delete) {
  db_->Put(kQueries, "test_delete", "baz");
  auto s = db_->Delete(kQueries, "test_delete");
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
}

TEST_F(DBHandleTests, test_scan) {
  db_->Put(kQueries, "test_scan_foo1", "baz");
  db_->Put(kQueries, "test_scan_foo2", "baz");
  db_->Put(kQueries, "test_scan_foo3", "baz");

  std::vector<std::string> keys;
  std::vector<std::string> expected = {
      "test_scan_foo1", "test_scan_foo2", "test_scan_foo3"};
  auto s = db_->Scan(kQueries, keys);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(keys.size(), 3U);
  for (const auto& i : expected) {
    EXPECT_NE(std::find(keys.begin(), keys.end(), i), keys.end());
  }
}

TEST_F(DBHandleTests, test_scan_limit) {
  db_->Put(kQueries, "test_scan_foo1", "baz");
  db_->Put(kQueries, "test_scan_foo2", "baz");
  db_->Put(kQueries, "test_scan_foo3", "baz");

  std::vector<std::string> keys;
  auto s = db_->Scan(kQueries, keys, 2);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(keys.size(), 2U);
}

TEST_F(DBHandleTests, test_rocksdb_loglevel) {
  // Make sure a log file was created.
  EXPECT_FALSE(pathExists(path_ + "/LOG"));

  // Make sure no log file is created.
  // RocksDB logs are intercepted and forwarded to the GLog sink.
  auto details = SQL::selectAllFrom("file", "path", EQUALS, path_ + "/LOG");
  ASSERT_EQ(details.size(), 0U);
}
}
