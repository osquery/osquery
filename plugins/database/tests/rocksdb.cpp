/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/database/tests/test_utils.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/sql/sql.h>
#include <plugins/database/rocksdb.h>

#include <boost/filesystem.hpp>

namespace osquery {

DECLARE_string(database_path);

class RocksDBDatabasePluginTests : public DatabasePluginTests {
 protected:
  std::string name() override {
    return "rocksdb";
  }

  void TearDown() override {
    DatabasePluginTests::TearDown();

    for (const auto& db_dir : db_dirs_) {
      removePath(db_dir);
    }
  }

  /// Holds db directories to cleanup in TearDown.
  std::vector<std::string> db_dirs_;
};

// Define the default set of database plugin operation tests.
CREATE_DATABASE_TESTS(RocksDBDatabasePluginTests);

TEST_F(RocksDBDatabasePluginTests, test_rocksdb_loglevel) {
  // Make sure a log file was created.
  EXPECT_FALSE(pathExists(path_ + "/LOG"));

  // Make sure no log file is created.
  // RocksDB logs are intercepted and forwarded to the GLog sink.
  auto details = SQL::selectAllFrom("file", "path", EQUALS, path_ + "/LOG");
  ASSERT_EQ(details.size(), 0U);
}

TEST_F(RocksDBDatabasePluginTests, test_corruption) {
  ASSERT_TRUE(pathExists(path_));
  ASSERT_FALSE(pathExists(path_ + ".backup"));

  // Mark the database as corrupted
  RocksDBDatabasePlugin::setCorrupted();
  resetDatabase();

  EXPECT_TRUE(pathExists(path_ + ".backup"));

  // Remove the backup and expect another reload to not create one.
  removePath(path_ + ".backup");
  ASSERT_FALSE(pathExists(path_ + ".backup"));

  resetDatabase();
  EXPECT_FALSE(pathExists(path_ + ".backup"));
}

TEST_F(RocksDBDatabasePluginTests, test_column_families_rollback) {
  auto db = RocksDBDatabasePlugin();
  const auto test_db_path =
      (boost::filesystem::temp_directory_path() /
       boost::filesystem::unique_path(
           "osquery.test_column_families_rollback.%%%%.%%%%.%%%%.%%%%.db"))
          .string();
  FLAGS_database_path = test_db_path;

  auto s = db.setUp();
  ASSERT_TRUE(s.ok()) << s.getMessage();

  db_dirs_.push_back(test_db_path);

  // Introduce a new column family.
  rocksdb::ColumnFamilyHandle* cf = nullptr;
  auto rs = db.db_->CreateColumnFamily(db.options_, "foo", &cf);
  ASSERT_TRUE(rs.ok()) << rs.ToString();
  db.db_->DestroyColumnFamilyHandle(cf);
  db.tearDown();

  // Open the existing database that has unknown column family "foo".
  auto db2 = RocksDBDatabasePlugin();
  s = db2.setUp();
  ASSERT_TRUE(s.ok()) << s.getMessage();
  db2.tearDown();
}
} // namespace osquery
