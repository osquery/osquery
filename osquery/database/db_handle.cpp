// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/database/db_handle.h"

#include <algorithm>
#include <mutex>
#include <stdexcept>

#include <glog/logging.h>
#include <rocksdb/env.h>
#include <rocksdb/options.h>

#include "osquery/core/status.h"

using osquery::core::Status;

namespace osquery { namespace db {

/////////////////////////////////////////////////////////////////////////////
// Constants
/////////////////////////////////////////////////////////////////////////////

const std::string kDBPath = "/tmp/rocksdb-osquery";

const std::string kConfigurations = "configurations";
const std::string kQueries = "queries";

const std::vector<std::string> kDomains = {
  kConfigurations,
  kQueries,
};

/////////////////////////////////////////////////////////////////////////////
// Locks
/////////////////////////////////////////////////////////////////////////////

static std::mutex transaction_lock_;

/////////////////////////////////////////////////////////////////////////////
// constructors and destructors
/////////////////////////////////////////////////////////////////////////////

DBHandle::DBHandle(std::string path, bool in_memory) {
  options_.create_if_missing = true;
  options_.create_missing_column_families = true;

  if (in_memory) {
    // Remove when upgrading to RocksDB 3.2
    // Replace with:
    // options_.env = rocksdb::NewMemEnv(rocksdb::Env::Default());
    throw std::domain_error("Requires RocksDB 3.3 https://fburl.com/27350299");
  }

  column_families_.push_back(
    rocksdb::ColumnFamilyDescriptor(
      rocksdb::kDefaultColumnFamilyName,
      rocksdb::ColumnFamilyOptions()
    )
  );

  for (auto cf_name : kDomains) {
    column_families_.push_back(
      rocksdb::ColumnFamilyDescriptor(
        cf_name,
        rocksdb::ColumnFamilyOptions()
      )
    );
  }

  status_ = rocksdb::DB::Open(
    options_,
    path,
    column_families_,
    &handles_,
    &db_
  );
}

DBHandle::~DBHandle() {
  DLOG(INFO) << "DBHandle::~DBHandle()";
  for (auto handle : handles_) {
    if (handle != nullptr) {
      delete handle;
      handle = nullptr;
    }
  }
  if (db_ != nullptr) {
    delete db_;
    db_ = nullptr;
  }
}

/////////////////////////////////////////////////////////////////////////////
// getInstance methods
/////////////////////////////////////////////////////////////////////////////
std::shared_ptr<DBHandle> DBHandle::getInstance() {
  return getInstance(kDBPath, false);
}

std::shared_ptr<DBHandle> DBHandle::getInstanceInMemory() {
  // Remove when upgrading to RocksDB 3.3
  throw std::domain_error("Requires RocksDB 3.3 https://fburl.com/27350299");
  return getInstance("", true);
}

std::shared_ptr<DBHandle> DBHandle::getInstanceAtPath(
  const std::string& path) {
  return getInstance(path, false);
}

std::shared_ptr<DBHandle> DBHandle::getInstance(
  const std::string& path, bool in_memory) {
  static std::shared_ptr<DBHandle> db_handle =
    std::shared_ptr<DBHandle>(new DBHandle(path, in_memory));
  return db_handle;
}

/////////////////////////////////////////////////////////////////////////////
// getters and setters
/////////////////////////////////////////////////////////////////////////////

osquery::core::Status DBHandle::getStatus() {
  return Status(status_.code(), status_.ToString());
}

rocksdb::DB* DBHandle::getDB() {
  return db_;
}

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
// Locking methods
/////////////////////////////////////////////////////////////////////////////


void DBHandle::startTransaction() {
  transaction_lock_.lock();
}

void DBHandle::endTransaction() {
  transaction_lock_.unlock();
}

/////////////////////////////////////////////////////////////////////////////
// Data manipulation methods
/////////////////////////////////////////////////////////////////////////////

osquery::core::Status DBHandle::Get(
  const std::string& domain,
  const std::string& key,
  std::string& value){
  auto s = getDB()->Get(
    rocksdb::ReadOptions(),
    getHandleForColumnFamily(domain),
    key,
    &value
  );
  return Status(s.code(), s.ToString());
}

osquery::core::Status DBHandle::Put(
  const std::string& domain,
  const std::string& key,
  const std::string& value) {
  auto s = getDB()->Put(
    rocksdb::WriteOptions(),
    getHandleForColumnFamily(domain),
    key,
    value
  );
  return Status(s.code(), s.ToString());
}

osquery::core::Status DBHandle::Delete(
  const std::string& domain,
  const std::string& key) {
  auto s = getDB()->Delete(
    rocksdb::WriteOptions(),
    getHandleForColumnFamily(domain),
    key
  );
  return Status(s.code(), s.ToString());
}

osquery::core::Status DBHandle::Scan(
  const std::string& domain,
  std::vector<std::string>& results) {
  auto it = getDB()->NewIterator(
    rocksdb::ReadOptions(),
    getHandleForColumnFamily(domain)
  );
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    results.push_back(it->key().ToString());
  }
  delete it;
  return Status(0, "OK");
}

}}
