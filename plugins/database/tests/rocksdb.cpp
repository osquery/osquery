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

#include <rocksdb/table.h>

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

TEST_F(RocksDBDatabasePluginTests, test_reset_keeps_data_and_size) {
  // Seed enough data to produce SST files, then reopen the database a few
  // times: every value must survive and the on-disk size must not grow once
  // the first reopen has merged the flushed files.
  const std::string value(1024, 'x');
  DatabaseStringValueList batch;
  for (int i = 0; i < 2000; i++) {
    batch.emplace_back("reset_" + std::to_string(i), value);
  }
  ASSERT_TRUE(setDatabaseBatch(kQueries, batch).ok());

  auto dir_size = [this]() {
    std::uintmax_t total = 0;
    for (const auto& entry : boost::filesystem::directory_iterator(path_)) {
      if (boost::filesystem::is_regular_file(entry)) {
        total += boost::filesystem::file_size(entry);
      }
    }
    return total;
  };

  resetDatabase();
  auto size_after_first = dir_size();
  resetDatabase();
  resetDatabase();
  // Allow a little slack for the manifest and log bookkeeping of a reopen.
  EXPECT_LE(dir_size(), size_after_first + 64 * 1024);

  std::string content;
  for (int i = 0; i < 2000; i += 199) {
    ASSERT_TRUE(
        getDatabaseValue(kQueries, "reset_" + std::to_string(i), content).ok());
    EXPECT_EQ(content, value);
  }
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

TEST_F(RocksDBDatabasePluginTests, test_events_ttl) {
  auto db = RocksDBDatabasePlugin();
  const auto test_db_path =
      (boost::filesystem::temp_directory_path() /
       boost::filesystem::unique_path(
           "osquery.test_events_ttl.%%%%.%%%%.%%%%.%%%%.db"))
          .string();
  FLAGS_database_path = test_db_path;

  // configures the column families
  auto s = db.setUp();
  ASSERT_TRUE(s.ok()) << s.getMessage();

  db_dirs_.push_back(test_db_path);

  auto handle = db.getHandleForColumnFamily(kEvents);
  ASSERT_NE(handle, nullptr) << kEvents;

  // ttl should be configured to 1d
  auto ttl = db.db_->GetOptions(handle).ttl;
  EXPECT_EQ(ttl, 24 * 60 * 60) << kEvents;

  db.tearDown();
}

TEST_F(RocksDBDatabasePluginTests, test_version_matches) {
  const auto expected_version = std::to_string(ROCKSDB_MAJOR) + "." +
                                std::to_string(ROCKSDB_MINOR) + "." +
                                std::to_string(ROCKSDB_PATCH);
  EXPECT_EQ(rocksdb::GetRocksVersionAsString(true), expected_version);
  EXPECT_GE(ROCKSDB_MAJOR, 6);
}

TEST_F(RocksDBDatabasePluginTests, test_open_close_cycles) {
  const auto test_db_path =
      (boost::filesystem::temp_directory_path() /
       boost::filesystem::unique_path(
           "osquery.test_open_close_cycles.%%%%.%%%%.%%%%.%%%%.db"))
          .string();
  FLAGS_database_path = test_db_path;
  db_dirs_.push_back(test_db_path);

  for (int i = 0; i < 50; ++i) {
    auto db = RocksDBDatabasePlugin();
    auto s = db.setUp();
    ASSERT_TRUE(s.ok()) << "Cycle " << i << " failed: " << s.getMessage();
    db.tearDown();
  }
}

TEST_F(RocksDBDatabasePluginTests, test_table_options_pinned) {
  auto db = RocksDBDatabasePlugin();
  const auto test_db_path =
      (boost::filesystem::temp_directory_path() /
       boost::filesystem::unique_path(
           "osquery.test_table_options_pinned.%%%%.%%%%.%%%%.%%%%.db"))
          .string();
  FLAGS_database_path = test_db_path;
  db_dirs_.push_back(test_db_path);

  auto s = db.setUp();
  ASSERT_TRUE(s.ok()) << s.getMessage();

  // Populate data in a domain so an SST file is flushed
  std::string value = "test_value";
  s = db.put(kQueries, "test_key", value);
  ASSERT_TRUE(s.ok()) << s.getMessage();

  rocksdb::FlushOptions flush_opts;
  auto rs = db.db_->Flush(flush_opts, db.getHandleForColumnFamily(kQueries));
  ASSERT_TRUE(rs.ok()) << rs.ToString();

  rocksdb::TablePropertiesCollection props;
  rs = db.db_->GetPropertiesOfAllTables(db.getHandleForColumnFamily(kQueries),
                                        &props);
  ASSERT_TRUE(rs.ok()) << rs.ToString();
  ASSERT_GT(props.size(), 0U);

  const auto* table_opts =
      db.options_.table_factory->GetOptions<rocksdb::BlockBasedTableOptions>();
  ASSERT_NE(table_opts, nullptr);
  EXPECT_EQ(table_opts->format_version, 5U)
      << "format_version must be pinned to 5 for backward compatibility";
  EXPECT_EQ(table_opts->checksum, rocksdb::kCRC32c)
      << "checksum must be pinned to kCRC32c for backward compatibility";

  // TableProperties::format_version is "reserved" and stays 0 on older
  // RocksDB releases (e.g. a system 6.22.1), so only check it when populated.
  // The table_factory assertions above cover the pin itself.
  for (const auto& kv : props) {
    if (kv.second->format_version != 0) {
      EXPECT_EQ(kv.second->format_version, 5U)
          << "format_version must be pinned to 5 for backward compatibility";
    }
  }

  db.tearDown();
}

TEST_F(RocksDBDatabasePluginTests, test_domain_isolation) {
  auto db = RocksDBDatabasePlugin();
  const auto test_db_path =
      (boost::filesystem::temp_directory_path() /
       boost::filesystem::unique_path(
           "osquery.test_domain_isolation.%%%%.%%%%.%%%%.%%%%.db"))
          .string();
  FLAGS_database_path = test_db_path;
  db_dirs_.push_back(test_db_path);

  auto s = db.setUp();
  ASSERT_TRUE(s.ok()) << s.getMessage();

  const std::string common_key = "shared_key";
  ASSERT_TRUE(db.put(kPersistentSettings, common_key, "config_val").ok());
  ASSERT_TRUE(db.put(kQueries, common_key, "queries_val").ok());
  ASSERT_TRUE(db.put(kEvents, common_key, "events_val").ok());
  ASSERT_TRUE(db.put(kLogs, common_key, "logs_val").ok());
  ASSERT_TRUE(db.put(kCarves, common_key, "carves_val").ok());

  std::string val;
  ASSERT_TRUE(db.get(kPersistentSettings, common_key, val).ok());
  EXPECT_EQ(val, "config_val");

  ASSERT_TRUE(db.get(kQueries, common_key, val).ok());
  EXPECT_EQ(val, "queries_val");

  ASSERT_TRUE(db.get(kEvents, common_key, val).ok());
  EXPECT_EQ(val, "events_val");

  ASSERT_TRUE(db.get(kLogs, common_key, val).ok());
  EXPECT_EQ(val, "logs_val");

  ASSERT_TRUE(db.get(kCarves, common_key, val).ok());
  EXPECT_EQ(val, "carves_val");

  db.tearDown();
}
} // namespace osquery
