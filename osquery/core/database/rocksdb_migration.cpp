/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <rocksdb/db.h>

#include <unordered_map>

#include <osquery/core/database/rocksdb_migration.h>
#include <osquery/utils/conversions/tryto.h>

#include <boost/filesystem.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

namespace osquery {

namespace fs = boost::filesystem;

namespace {

enum DatabaseSchemaVersion {
  kDatabaseSchemaV1 = 1,
  kDatabaseSchemaV2 = 2,
  kDatabaseSchemaV3 = 3,
  kDatabaseSchemaVersionCurrent = kDatabaseSchemaV3,
};

class RocksdbMigration final {
 public:
  RocksdbMigration(const std::string& path);
  ExpectedSuccess<RocksdbMigrationError> migrateIfNeeded();

 private:
  struct DatabaseHandle {
    std::unique_ptr<rocksdb::DB> db_handle;
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
};

} // namespace

RocksdbMigration::RocksdbMigration(const std::string& path) {
  auto boost_path = fs::path(path).make_preferred();
  source_path_ = boost_path.string();
}

ExpectedSuccess<RocksdbMigrationError> RocksdbMigration::migrateIfNeeded() {
  auto open_result = openDatabase(source_path_, false, false);
  if (open_result) {
    auto db_handle = open_result.take();
    auto version_result = getVersion(db_handle);
    if (version_result) {
      int version = version_result.take();
      if (version != kDatabaseSchemaVersionCurrent) {
        migrateFromVersion(version);
      } else {
        return Success();
      }
    } else {
      return version_result.takeError();
    }
  } else {
    // InvalidArgument means that db does not exists
    if (open_result.getErrorCode() == RocksdbMigrationError::InvalidArgument) {
      return Success();
    } else {
      return open_result.takeError();
    }
  }
  return Success();
}

ExpectedSuccess<RocksdbMigrationError> RocksdbMigration::dropDbMigration(
    const std::string& src_path, const std::string& dst_path) {
  auto dst_db = openDatabase(dst_path, true, true);
  if (dst_db) {
    return Success();
  }
  return dst_db.takeError();
}

void RocksdbMigration::buildMigrationMap() {
  // No migration map at this stage, will be added as separate commit
}

ExpectedSuccess<RocksdbMigrationError> RocksdbMigration::migrateFromVersion(
    int original_version) {
  buildMigrationMap();
  std::string src_path = source_path_;
  std::string dst_path = randomOutputPath();
  bool drop_src_data = false;
  for (int version = original_version;
       version < kDatabaseSchemaVersionCurrent;) {
    auto iter = migration_map_.find(version);
    if (iter == migration_map_.end()) {
      return createError(RocksdbMigrationError::NoMigrationFromCurrentVersion)
             << "No migration logic from version: " << version;
    }
    VLOG(1) << "Migrating from version: " << version
            << ". Src path: " << src_path << ". Dst path: " << dst_path;

    auto migration_result = iter->second(src_path, dst_path);
    if (migration_result) {
      int new_version = migration_result.take();
      if (new_version <= version) {
        return createError(RocksdbMigrationError::MigrationLogicError)
               << "New version(" << version << ") is lower or same as old("
               << new_version << ")";
      }
      version = new_version;
    } else {
      return migration_result.takeError();
    }

    if (drop_src_data) {
      VLOG(1) << "Destroying db at path: " << src_path;
      rocksdb::DestroyDB(src_path, rocksdb::Options());
    }
    drop_src_data = true;
    src_path = dst_path;
    dst_path = randomOutputPath();
  }

  std::string temp_store = randomOutputPath();
  auto original_src = source_path_;
  auto new_src = src_path;

  auto move = moveDb(original_src, temp_store);
  if (move) {
    move = moveDb(new_src, original_src);
    if (move) {
      rocksdb::DestroyDB(temp_store, rocksdb::Options());
      return Success();
    }
  }
  return move.takeError();
}

ExpectedSuccess<RocksdbMigrationError> RocksdbMigration::moveDb(
    const std::string& src_path, const std::string& dst_path) {
  boost::system::error_code ec;
  if (fs::exists(fs::path(dst_path), ec)) {
    return createError(RocksdbMigrationError::FailMoveDatabase)
           << "Database at dst path already exists or path is not accessible. "
              "Path: "
           << dst_path << "Error: " << ec.value() << " " << ec.message();
  }

  fs::rename(src_path, dst_path, ec);
  if (!ec) {
    return createError(RocksdbMigrationError::FailMoveDatabase)
           << "Move failed: " << ec.value() << " " << ec.message();
  }
  return Success();
}

Expected<RocksdbMigration::DatabaseHandle, RocksdbMigrationError>
RocksdbMigration::openDatabase(const std::string& path,
                               bool create_if_missing,
                               bool error_if_exists) {
  DatabaseHandle handle;
  handle.options.OptimizeForSmallDb();
  handle.options.create_if_missing = create_if_missing;
  handle.options.error_if_exists = error_if_exists;
  handle.path = path;
  std::vector<std::string> column_families;
  rocksdb::DB::ListColumnFamilies(handle.options, path, &column_families);

  std::vector<rocksdb::ColumnFamilyDescriptor> descriptors;
  for (const auto& column : column_families) {
    descriptors.push_back(
        rocksdb::ColumnFamilyDescriptor(column, handle.options));
  }
  std::vector<rocksdb::ColumnFamilyHandle*> column_family_handles;
  rocksdb::DB* db = nullptr;
  auto status = rocksdb::DB::Open(
      handle.options, path, descriptors, &column_family_handles, &db);
  if (status.IsInvalidArgument()) {
    return createError(RocksdbMigrationError::InvalidArgument)
           << status.ToString();
  }
  if (!status.ok()) {
    return createError(RocksdbMigrationError::FailToOpen) << status.ToString();
  }
  handle.db_handle = std::unique_ptr<rocksdb::DB>(db);
  for (const auto& ptr : column_family_handles) {
    handle.handles[ptr->GetName()] =
        std::unique_ptr<rocksdb::ColumnFamilyHandle>(ptr);
  }
  return std::move(handle);
}

Expected<int, RocksdbMigrationError> RocksdbMigration::getVersion(
    const DatabaseHandle& db) {
  rocksdb::ReadOptions options;
  options.verify_checksums = true;
  auto handle_iter = db.handles.find("configurations");
  if (handle_iter != db.handles.end()) {
    // Try to get new version first
    // Version stored as string value to help analyze db by tools
    std::string version_str;

    rocksdb::ColumnFamilyHandle* raw_handle = handle_iter->second.get();

    auto status = db.db_handle->Get(options,
                                    raw_handle,
                                    std::string("database_schema_version"),
                                    &version_str);
    if (status.IsNotFound()) {
      // Fallback to old version storage
      auto default_family_handle_iter = db.handles.find("default");
      if (default_family_handle_iter != db.handles.end()) {
        status = db.db_handle->Get(options,
                                   default_family_handle_iter->second.get(),
                                   std::string("results_version"),
                                   &version_str);
      }
    }
    if (!status.ok()) {
      return createError(RocksdbMigrationError::FailToGetVersion)
             << status.ToString();
    }
    auto result = tryTo<int>(version_str);
    if (result) {
      return *result;
    }
    return createError(RocksdbMigrationError::FailToGetVersion,
                       result.takeError());
  }
  return createError(RocksdbMigrationError::FailToGetVersion)
         << "Verion data is not found";
}

std::string RocksdbMigration::randomOutputPath() {
  auto path = fs::path(OSQUERY_HOME);
  boost::uuids::uuid uuid = boost::uuids::random_generator()();
  path.append("migration");
  path.append(boost::uuids::to_string(uuid));
  return path.string();
}

ExpectedSuccess<RocksdbMigrationError> migrateRocksDBDatabase(
    const std::string& path) {
  auto migration = std::make_unique<RocksdbMigration>(path);
  return migration->migrateIfNeeded();
}

} // namespace osquery
