/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <osquery/expected.h>
#include <rocksdb/db.h>

#include <unordered_map>

namespace osquery {

enum DatabaseSchemaVersion {
  kDatabaseSchemaV1 = 1,
  kDatabaseSchemaV2 = 2,
  kDatabaseSchemaV3 = 3,
  kDatabaseSchemaVersionCurrent = kDatabaseSchemaV3,
};

enum class RocksdbMigrationError {
  InvalidArgument = 1,
  FailToOpen = 2,
  FailToGetVersion = 3,
  NoMigrationFromCurrentVersion = 5,
  MigrationLogicError = 6,
  FailToOpenSrcDatabase = 7,
  FailMoveDatabase = 8,
};

class RocksdbMigration final {
 public:
  static ExpectedSuccess<RocksdbMigrationError> migrateDatabase(
      const std::string& path);
  RocksdbMigration(const std::string& path);

 private:
  struct DatabaseHandle {
    std::unique_ptr<rocksdb::DB> db_handle = nullptr;
    rocksdb::Options options;
    std::string path;
    std::unordered_map<std::string,
                       std::unique_ptr<rocksdb::ColumnFamilyHandle>>
        handles;
  };
  DatabaseHandle input_db_;
  DatabaseHandle output_db_;

  std::string source_path_;
  std::unordered_map<int,
                     std::function<Expected<int, RocksdbMigrationError>(
                         const std::string& src, const std::string& dst)>>
      migration_map_;

 private:
  static Expected<DatabaseHandle, RocksdbMigrationError> openDatabase(
      const std::string& path, bool create_if_missing, bool error_if_exists);
  static ExpectedSuccess<RocksdbMigrationError> dropDbMigration(
      const std::string& src_path, const std::string& dst_path);
  static ExpectedSuccess<RocksdbMigrationError> moveDb(
      const std::string& src_path, const std::string& dst_path);

  Expected<int, RocksdbMigrationError> getVersion(const DatabaseHandle& db);
  ExpectedSuccess<RocksdbMigrationError> migrateFromVersion(int version);

  void buildMigrationMap();

  std::string randomOutputPath();

  ExpectedSuccess<RocksdbMigrationError> migrateIfNeeded();
};

} // namespace osquery
