/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <mutex>

#include <sys/stat.h>

#include <snappy.h>

#include <rocksdb/db.h>
#include <rocksdb/env.h>
#include <rocksdb/options.h>

#include <osquery/database.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/filesystem/fileops.h"

namespace osquery {

DECLARE_string(database_path);

class GlogRocksDBLogger : public rocksdb::Logger {
 public:
  // We intend to override a virtual method that is overloaded.
  using rocksdb::Logger::Logv;
  void Logv(const char* format, va_list ap) override;
};

class RocksDBDatabasePlugin : public DatabasePlugin {
 public:
  /// Data retrieval method.
  Status get(const std::string& domain,
             const std::string& key,
             std::string& value) const override;

  /// Data storage method.
  Status put(const std::string& domain,
             const std::string& key,
             const std::string& value) override;

  /// Data removal method.
  Status remove(const std::string& domain, const std::string& k) override;

  /// Data range removal method.
  Status removeRange(const std::string& domain,
                     const std::string& low,
                     const std::string& high) override;

  /// Key/index lookup method.
  Status scan(const std::string& domain,
              std::vector<std::string>& results,
              const std::string& prefix,
              size_t max = 0) const override;

 public:
  /// Database workflow: open and setup.
  Status setUp() override;

  /// Database workflow: close and cleanup.
  void tearDown() override {
    close();
  }

  /// Need to tear down open resources,
  virtual ~RocksDBDatabasePlugin() {
    close();
  }

 private:
  /// Obtain a close lock and release resources.
  void close();

  /**
   * @brief Private helper around accessing the column family handle for a
   * specific column family, based on its name
   */
  rocksdb::ColumnFamilyHandle* getHandleForColumnFamily(
      const std::string& cf) const;

  /**
   * @brief Helper method which can be used to get a raw pointer to the
   * underlying RocksDB database handle
   *
   * @return a pointer to the underlying RocksDB database handle
   */
  rocksdb::DB* getDB() const;

  /**
   * @brief Helper method to repair a corrupted db. Best effort only.
   *
   * @return nothing.
   */
  void repairDB();

 private:
  bool initialized_{false};

  /// The database handle
  rocksdb::DB* db_{nullptr};

  /// RocksDB logger instance.
  std::shared_ptr<GlogRocksDBLogger> logger_{nullptr};

  /// Column family descriptors which are used to connect to RocksDB
  std::vector<rocksdb::ColumnFamilyDescriptor> column_families_;

  /// A vector of pointers to column family handles
  std::vector<rocksdb::ColumnFamilyHandle*> handles_;

  /// The RocksDB connection options that are used to connect to RocksDB
  rocksdb::Options options_;

  /// Deconstruction mutex.
  Mutex close_mutex_;
};

/// Backing-storage provider for osquery internal/core.
REGISTER_INTERNAL(RocksDBDatabasePlugin, "database", "rocksdb");

void GlogRocksDBLogger::Logv(const char* format, va_list ap) {
  // Convert RocksDB log to string and check if header or level-ed log.
  std::string log_line;
  {
    char buffer[501] = {0};
    vsnprintf(buffer, 500, format, ap);
    va_end(ap);
    if (buffer[0] != '[' || (buffer[1] != 'E' && buffer[1] != 'W')) {
      return;
    }

    log_line = buffer;
  }

  // There is a spurious warning on first open.
  if (log_line.find("Error when reading") == std::string::npos) {
    // RocksDB calls are non-reentrant. Since this callback is made in the
    // context of a RocksDB API call, turn log forwarding off to prevent the
    // logger from trying to make a call back into RocksDB and causing a
    // deadlock.
    LOG(INFO) << "RocksDB: " << log_line;
  }
}

Status RocksDBDatabasePlugin::setUp() {
  if (!kDBHandleOptionAllowOpen) {
    LOG(WARNING) << RLOG(1629) << "Not allowed to set up database plugin";
  }

  if (!initialized_) {
    initialized_ = true;
    options_.OptimizeForSmallDb();

    // Set meta-data (mostly) handling options.
    options_.create_if_missing = true;
    options_.create_missing_column_families = true;
    options_.info_log_level = rocksdb::ERROR_LEVEL;
    options_.log_file_time_to_roll = 0;
    options_.keep_log_file_num = 10;
    options_.max_log_file_size = 1024 * 1024 * 1;
    options_.stats_dump_period_sec = 0;
    options_.max_manifest_file_size = 1024 * 500;

    // Performance and optimization settings.
    options_.compression = rocksdb::kNoCompression;
    options_.compaction_style = rocksdb::kCompactionStyleLevel;
    options_.arena_block_size = (4 * 1024);
    options_.write_buffer_size = (4 * 1024) * 256; // 100 blocks.
    options_.max_write_buffer_number = 4;
    options_.min_write_buffer_number_to_merge = 1;
    options_.max_background_flushes = 4;

    // Create an environment to replace the default logger.
    if (logger_ == nullptr) {
      logger_ = std::make_shared<GlogRocksDBLogger>();
    }
    options_.info_log = logger_;

    column_families_.push_back(rocksdb::ColumnFamilyDescriptor(
        rocksdb::kDefaultColumnFamilyName, options_));

    for (const auto& cf_name : kDomains) {
      column_families_.push_back(
          rocksdb::ColumnFamilyDescriptor(cf_name, options_));
    }
  }

  // Consume the current settings.
  // A configuration update may change them, but that does not affect state.
  path_ = fs::path(FLAGS_database_path).make_preferred().string();

  if (pathExists(path_).ok() && !isReadable(path_).ok()) {
    return Status(1, "Cannot read RocksDB path: " + path_);
  }

  if (!DatabasePlugin::kCheckingDB) {
    VLOG(1) << "Opening RocksDB handle: " << path_;
  }

  // Tests may trash calls to setUp, make sure subsequent calls do not leak.
  close();

  // Attempt to create a RocksDB instance and handles.
  auto s =
      rocksdb::DB::Open(options_, path_, column_families_, &handles_, &db_);

  if (s.IsCorruption()) {
    // The database is corrupt - try to repair it
    repairDB();
    s = rocksdb::DB::Open(options_, path_, column_families_, &handles_, &db_);
  }

  if (!s.ok() || db_ == nullptr) {
    LOG(INFO) << "Rocksdb open failed (" << s.code() << ":" << s.subcode()
              << ") " << s.ToString();
    if (kDBHandleOptionRequireWrite) {
      // A failed open in R/W mode is a runtime error.
      return Status(1, s.ToString());
    }

    if (!DatabasePlugin::kCheckingDB) {
      LOG(INFO) << "Opening RocksDB failed: Continuing with read-only support";
    }
#if !defined(ROCKSDB_LITE)
    // RocksDB LITE does not support readonly mode.
    // The database was readable but could not be opened, either (1) it is not
    // writable or (2) it is already opened by another process.
    // Try to open the database in a ReadOnly mode.
    rocksdb::DB::OpenForReadOnly(
        options_, path_, column_families_, &handles_, &db_);
#endif
    // Also disable event publishers.
    Flag::updateValue("disable_events", "true");
    read_only_ = true;
  }

  // RocksDB may not create/append a directory with acceptable permissions.
  if (!read_only_ && platformChmod(path_, S_IRWXU) == false) {
    return Status(1, "Cannot set permissions on RocksDB path: " + path_);
  }
  return Status(0);
}

void RocksDBDatabasePlugin::close() {
  WriteLock lock(close_mutex_);
  if (db_ != nullptr) {
    db_->Flush(rocksdb::FlushOptions());
  }
  for (auto handle : handles_) {
    delete handle;
  }
  handles_.clear();

  if (db_ != nullptr) {
    delete db_;
    db_ = nullptr;
  }
}

void RocksDBDatabasePlugin::repairDB() {
  // ROCKSDB_LITE does not have a RepairDB method. No option but to delete the
  // corrupted DB
  LOG(INFO) << "Deleting corrupted database files";
  std::vector<std::string> file_names;
  auto s = listFilesInDirectory(path_, file_names);
  if (s.ok()) {
    for (auto file : file_names) {
      osquery::remove(file);
    }
  } else {
    LOG(INFO) << "Unable to list " << path_ << ": " << s.toString();
  }
}

rocksdb::DB* RocksDBDatabasePlugin::getDB() const {
  return db_;
}

rocksdb::ColumnFamilyHandle* RocksDBDatabasePlugin::getHandleForColumnFamily(
    const std::string& cf) const {
  try {
    for (size_t i = 0; i < kDomains.size(); i++) {
      if (kDomains[i] == cf) {
        return handles_[i];
      }
    }
  } catch (const std::exception& /* e */) {
    // pass through and return nullptr
  }
  return nullptr;
}

Status RocksDBDatabasePlugin::get(const std::string& domain,
                                  const std::string& key,
                                  std::string& value) const {
  if (getDB() == nullptr) {
    return Status(1, "Database not opened");
  }
  auto cfh = getHandleForColumnFamily(domain);
  if (cfh == nullptr) {
    return Status(1, "Could not get column family for " + domain);
  }
  auto s = getDB()->Get(rocksdb::ReadOptions(), cfh, key, &value);
  return Status(s.code(), s.ToString());
}

Status RocksDBDatabasePlugin::put(const std::string& domain,
                                  const std::string& key,
                                  const std::string& value) {
  if (read_only_) {
    return Status(0, "Database in readonly mode");
  }

  auto cfh = getHandleForColumnFamily(domain);
  if (cfh == nullptr) {
    return Status(1, "Could not get column family for " + domain);
  }

  auto options = rocksdb::WriteOptions();
  // Events should be fast, and do not need to force syncs.
  if (kEvents != domain) {
    options.sync = true;
  } else {
    options.disableWAL = true;
  }
  auto s = getDB()->Put(options, cfh, key, value);
  if (s.code() != 0 && s.IsIOError()) {
    // An error occurred, check if it is an IO error and remove the offending
    // specific filename or log name.
    std::string error_string = s.ToString();
    size_t error_pos = error_string.find_last_of(":");
    if (error_pos != std::string::npos) {
      return Status(s.code(), "IOError: " + error_string.substr(error_pos + 2));
    }
  }
  return Status(s.code(), s.ToString());
}

Status RocksDBDatabasePlugin::remove(const std::string& domain,
                                     const std::string& key) {
  if (read_only_) {
    return Status(0, "Database in readonly mode");
  }

  auto cfh = getHandleForColumnFamily(domain);
  if (cfh == nullptr) {
    return Status(1, "Could not get column family for " + domain);
  }
  auto options = rocksdb::WriteOptions();

  // We could sync here, but large deletes will cause multi-syncs.
  // For example: event record expirations found in an expired index.
  if (kEvents != domain) {
    options.sync = true;
  }
  auto s = getDB()->Delete(options, cfh, key);
  return Status(s.code(), s.ToString());
}

Status RocksDBDatabasePlugin::removeRange(const std::string& domain,
                                          const std::string& low,
                                          const std::string& high) {
  if (read_only_) {
    return Status(0, "Database in readonly mode");
  }

  auto cfh = getHandleForColumnFamily(domain);
  if (cfh == nullptr) {
    return Status(1, "Could not get column family for " + domain);
  }
  auto options = rocksdb::WriteOptions();

  // We could sync here, but large deletes will cause multi-syncs.
  // For example: event record expirations found in an expired index.
  if (kEvents != domain) {
    options.sync = true;
  }
  auto s = getDB()->DeleteRange(options, cfh, low, high);
  if (low <= high) {
    s = getDB()->Delete(options, cfh, high);
  }
  return Status(s.code(), s.ToString());
}

Status RocksDBDatabasePlugin::scan(const std::string& domain,
                                   std::vector<std::string>& results,
                                   const std::string& prefix,
                                   size_t max) const {
  if (getDB() == nullptr) {
    return Status(1, "Database not opened");
  }

  auto cfh = getHandleForColumnFamily(domain);
  if (cfh == nullptr) {
    return Status(1, "Could not get column family for " + domain);
  }
  auto options = rocksdb::ReadOptions();
  options.verify_checksums = false;
  options.fill_cache = false;
  auto it = getDB()->NewIterator(options, cfh);
  if (it == nullptr) {
    return Status(1, "Could not get iterator for " + domain);
  }

  size_t count = 0;
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    auto key = it->key().ToString();
    if (key.find(prefix) == 0) {
      results.push_back(std::move(key));
      if (max > 0 && ++count >= max) {
        break;
      }
    }
  }
  delete it;
  return Status(0, "OK");
}
}
