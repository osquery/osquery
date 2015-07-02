/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <algorithm>
#include <mutex>
#include <stdexcept>

#include <sys/stat.h>

#include <rocksdb/env.h>
#include <rocksdb/options.h>
#include <snappy.h>

#include <osquery/database.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/status.h>

#include "osquery/database/db_handle.h"

namespace osquery {

class RocksDatabasePlugin : public DatabasePlugin {
 public:
  /// Data retrieval method.
  Status get(const std::string& domain,
             const std::string& key,
             std::string& value) const;

  /// Data storage method.
  Status put(const std::string& domain,
             const std::string& key,
             const std::string& value);

  /// Data removal method.
  Status remove(const std::string& domain, const std::string& k);

  /// Key/index lookup method.
  Status scan(const std::string& domain,
              std::vector<std::string>& results) const;
};

/// Backing-storage provider for osquery internal/core.
REGISTER_INTERNAL(RocksDatabasePlugin, "database", "rocks");

/////////////////////////////////////////////////////////////////////////////
// Constants
/////////////////////////////////////////////////////////////////////////////

const std::string kPersistentSettings = "configurations";
const std::string kQueries = "queries";
const std::string kEvents = "events";
const std::string kLogs = "logs";

/**
 * @brief A const vector of column families in RocksDB
 *
 * RocksDB has a concept of "column families" which are kind of like tables
 * in other databases. kDomainds is populated with a list of all column
 * families. If a string exists in kDomains, it's a column family in the
 * database.
 */
const std::vector<std::string> kDomains = {
    kPersistentSettings, kQueries, kEvents, kLogs
};

CLI_FLAG(string,
         database_path,
         "/var/osquery/osquery.db",
         "If using a disk-based backing store, specify a path");
FLAG_ALIAS(std::string, db_path, database_path);

CLI_FLAG(bool,
         database_in_memory,
         false,
         "Keep osquery backing-store in memory");
FLAG_ALIAS(bool, use_in_memory_database, database_in_memory);

/////////////////////////////////////////////////////////////////////////////
// constructors and destructors
/////////////////////////////////////////////////////////////////////////////

DBHandle::DBHandle(const std::string& path, bool in_memory) {
  options_.create_if_missing = true;
  options_.create_missing_column_families = true;
  options_.info_log_level = rocksdb::WARN_LEVEL;
  options_.log_file_time_to_roll = 0;
  options_.keep_log_file_num = 10;
  options_.max_log_file_size = 1024 * 1024 * 1;
  options_.compaction_style = rocksdb::kCompactionStyleLevel;
  options_.write_buffer_size = 1 * 1024 * 1024;
  options_.max_write_buffer_number = 2;
  options_.max_background_compactions = 1;

  if (in_memory) {
    // Remove when MemEnv is included in librocksdb
    // options_.env = rocksdb::NewMemEnv(rocksdb::Env::Default());
    throw std::runtime_error("Requires MemEnv");
  }

  if (pathExists(path).ok() && !isWritable(path).ok()) {
    throw std::runtime_error("Cannot write to RocksDB path: " + path);
  }

  column_families_.push_back(rocksdb::ColumnFamilyDescriptor(
      rocksdb::kDefaultColumnFamilyName, rocksdb::ColumnFamilyOptions()));

  for (const auto& cf_name : kDomains) {
    column_families_.push_back(rocksdb::ColumnFamilyDescriptor(
        cf_name, rocksdb::ColumnFamilyOptions()));
  }

  VLOG(1) << "Opening RocksDB handle: " << path;
  auto s = rocksdb::DB::Open(options_, path, column_families_, &handles_, &db_);
  if (!s.ok()) {
    throw std::runtime_error(s.ToString());
  }

  // RocksDB may not create/append a directory with acceptable permissions.
  if (chmod(path.c_str(), S_IRWXU) != 0) {
    throw std::runtime_error("Cannot set permissions on RocksDB path: " + path);
  }
}

DBHandle::~DBHandle() {
  for (auto handle : handles_) {
    delete handle;
  }
  delete db_;
}

/////////////////////////////////////////////////////////////////////////////
// getInstance methods
/////////////////////////////////////////////////////////////////////////////

DBHandleRef DBHandle::getInstance() {
  return getInstance(FLAGS_database_path, FLAGS_database_in_memory);
}

bool DBHandle::checkDB() {
  try {
    auto handle = DBHandle(FLAGS_database_path, FLAGS_database_in_memory);
  } catch (const std::exception& e) {
    return false;
  }
  return true;
}

DBHandleRef DBHandle::getInstanceInMemory() {
  return getInstance("", true);
}

DBHandleRef DBHandle::getInstanceAtPath(const std::string& path) {
  return getInstance(path, false);
}

DBHandleRef DBHandle::getInstance(const std::string& path, bool in_memory) {
  static DBHandleRef db_handle = DBHandleRef(new DBHandle(path, in_memory));
  return db_handle;
}

/////////////////////////////////////////////////////////////////////////////
// getters and setters
/////////////////////////////////////////////////////////////////////////////

rocksdb::DB* DBHandle::getDB() { return db_; }

rocksdb::ColumnFamilyHandle* DBHandle::getHandleForColumnFamily(
    const std::string& cf) {
  try {
    for (int i = 0; i < kDomains.size(); i++) {
      if (kDomains[i] == cf) {
        return handles_[i];
      }
    }
  } catch (const std::exception& e) {
    // pass through and return nullptr
  }
  return nullptr;
}

/////////////////////////////////////////////////////////////////////////////
// Data manipulation methods
/////////////////////////////////////////////////////////////////////////////

Status DBHandle::Get(const std::string& domain,
                     const std::string& key,
                     std::string& value) {
  auto cfh = getHandleForColumnFamily(domain);
  if (cfh == nullptr) {
    return Status(1, "Could not get column family for " + domain);
  }
  auto s = getDB()->Get(rocksdb::ReadOptions(), cfh, key, &value);
  return Status(s.code(), s.ToString());
}

Status DBHandle::Put(const std::string& domain,
                     const std::string& key,
                     const std::string& value) {
  auto cfh = getHandleForColumnFamily(domain);
  if (cfh == nullptr) {
    return Status(1, "Could not get column family for " + domain);
  }
  auto s = getDB()->Put(rocksdb::WriteOptions(), cfh, key, value);
  return Status(s.code(), s.ToString());
}

Status DBHandle::Delete(const std::string& domain, const std::string& key) {
  auto cfh = getHandleForColumnFamily(domain);
  if (cfh == nullptr) {
    return Status(1, "Could not get column family for " + domain);
  }
  auto s = getDB()->Delete(rocksdb::WriteOptions(), cfh, key);
  return Status(s.code(), s.ToString());
}

Status DBHandle::Scan(const std::string& domain,
                      std::vector<std::string>& results) {
  auto cfh = getHandleForColumnFamily(domain);
  if (cfh == nullptr) {
    return Status(1, "Could not get column family for " + domain);
  }
  auto it = getDB()->NewIterator(rocksdb::ReadOptions(), cfh);
  if (it == nullptr) {
    return Status(1, "Could not get iterator for " + domain);
  }
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    results.push_back(it->key().ToString());
  }
  delete it;
  return Status(0, "OK");
}

Status RocksDatabasePlugin::get(const std::string& domain,
                                const std::string& key,
                                std::string& value) const {
  return DBHandle::getInstance()->Get(domain, key, value);
}

Status RocksDatabasePlugin::put(const std::string& domain,
                                const std::string& key,
                                const std::string& value) {
  return DBHandle::getInstance()->Put(domain, key, value);
}

Status RocksDatabasePlugin::remove(const std::string& domain,
                                   const std::string& key) {
  return DBHandle::getInstance()->Delete(domain, key);
}

Status RocksDatabasePlugin::scan(const std::string& domain,
                                 std::vector<std::string>& results) const {
  return DBHandle::getInstance()->Scan(domain, results);
}
}
