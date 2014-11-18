// Copyright 2004-present Facebook. All Rights Reserved.

#include <algorithm>
#include <mutex>
#include <stdexcept>

#include <glog/logging.h>
#include <rocksdb/env.h>
#include <rocksdb/options.h>

#include "osquery/database/db_handle.h"
#include "osquery/filesystem.h"
#include "osquery/status.h"

using osquery::Status;

namespace osquery {

/////////////////////////////////////////////////////////////////////////////
// Constants
/////////////////////////////////////////////////////////////////////////////

const std::string kConfigurations = "configurations";
const std::string kQueries = "queries";
const std::string kEvents = "events";

const std::vector<std::string> kDomains = {kConfigurations, kQueries, kEvents};

DEFINE_osquery_flag(string,
                    db_path,
                    "/var/osquery/osquery.db",
                    "If using a disk-based backing store, specify a path.");

DEFINE_osquery_flag(bool,
                    use_in_memory_database,
                    false,
                    "Keep osquery backing-store in memory.");

/////////////////////////////////////////////////////////////////////////////
// constructors and destructors
/////////////////////////////////////////////////////////////////////////////

DBHandle::DBHandle(const std::string& path, bool in_memory) {
  options_.create_if_missing = true;
  options_.create_missing_column_families = true;

  if (in_memory) {
    // Remove when upgrading to RocksDB 3.3
    // options_.env = rocksdb::NewMemEnv(rocksdb::Env::Default());
    throw std::runtime_error("Required RocksDB 3.3 (and setMemEnv)");
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

  auto s = rocksdb::DB::Open(options_, path, column_families_, &handles_, &db_);
  if (!s.ok()) {
    throw std::runtime_error(s.ToString());
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
std::shared_ptr<DBHandle> DBHandle::getInstance() {
  return getInstance(FLAGS_db_path, FLAGS_use_in_memory_database);
}

std::shared_ptr<DBHandle> DBHandle::getInstanceInMemory() {
  return getInstance("", true);
}

std::shared_ptr<DBHandle> DBHandle::getInstanceAtPath(const std::string& path) {
  return getInstance(path, false);
}

std::shared_ptr<DBHandle> DBHandle::getInstance(const std::string& path,
                                                bool in_memory) {
  static std::shared_ptr<DBHandle> db_handle =
      std::shared_ptr<DBHandle>(new DBHandle(path, in_memory));
  return db_handle;
}

/////////////////////////////////////////////////////////////////////////////
// getters and setters
/////////////////////////////////////////////////////////////////////////////

rocksdb::DB* DBHandle::getDB() { return db_; }

rocksdb::ColumnFamilyHandle* DBHandle::getHandleForColumnFamily(
    const std::string& cf) {
  for (int i = 0; i < kDomains.size(); i++) {
    if (kDomains[i] == cf) {
      return handles_[i];
    }
  }
  return nullptr;
}

/////////////////////////////////////////////////////////////////////////////
// Data manipulation methods
/////////////////////////////////////////////////////////////////////////////

osquery::Status DBHandle::Get(const std::string& domain,
                              const std::string& key,
                              std::string& value) {
  auto s = getDB()->Get(
      rocksdb::ReadOptions(), getHandleForColumnFamily(domain), key, &value);
  return Status(s.code(), s.ToString());
}

osquery::Status DBHandle::Put(const std::string& domain,
                              const std::string& key,
                              const std::string& value) {
  auto s = getDB()->Put(
      rocksdb::WriteOptions(), getHandleForColumnFamily(domain), key, value);
  return Status(s.code(), s.ToString());
}

osquery::Status DBHandle::Delete(const std::string& domain,
                                 const std::string& key) {
  auto s = getDB()->Delete(
      rocksdb::WriteOptions(), getHandleForColumnFamily(domain), key);
  return Status(s.code(), s.ToString());
}

osquery::Status DBHandle::Scan(const std::string& domain,
                               std::vector<std::string>& results) {
  auto it = getDB()->NewIterator(rocksdb::ReadOptions(),
                                 getHandleForColumnFamily(domain));
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    results.push_back(it->key().ToString());
  }
  delete it;
  return Status(0, "OK");
}
}
