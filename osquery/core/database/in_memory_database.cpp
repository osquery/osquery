/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/core/database/in_memory_database.h>
#include <osquery/database.h>
#include <osquery/logger.h>

#include <boost/algorithm/string.hpp>
#include <boost/core/demangle.hpp>

namespace osquery {

template <typename StorageType>
std::vector<std::string> InMemoryStorage<StorageType>::getKeys(
    const std::string& prefix) const {
  std::vector<std::string> result;
  for (const auto& iter : storage_) {
    if (boost::starts_with(iter.first, prefix)) {
      result.push_back(iter.first);
    }
  }
  return result;
}

template <typename StorageType>
void InMemoryStorage<StorageType>::put(const std::string& key,
                                       const StorageType value) {
  storage_[key] = value;
}

template <typename StorageType>
Expected<StorageType, DatabaseError> InMemoryStorage<StorageType>::get(
    const std::string& key) const {
  auto iter = storage_.find(key);
  if (iter != storage_.end()) {
    return iter->second;
  }
  return createError(DatabaseError::KeyNotFound, "Can't find value for key ")
         << key;
}

void InMemoryDatabase::close() {
  VLOG(1) << "Closing db... ";
  debug_only::verifyTrue(is_open_, "database is not open");
  is_open_ = false;
  destroyDB();
}

ExpectedSuccess<DatabaseError> InMemoryDatabase::destroyDB() {
  VLOG(1) << "Destroying in memory db";
  storage_.clear();
  return Success();
}

ExpectedSuccess<DatabaseError> InMemoryDatabase::open() {
  debug_only::verifyTrue(!is_open_, "database is already open");
  for (const auto& domain : kDomains) {
    storage_[domain] = std::make_unique<InMemoryStorage<DataType>>();
  }
  is_open_ = true;
  return Success();
}

Error<DatabaseError> InMemoryDatabase::domainNotFoundError(
    const std::string& domain) const {
  return createError(DatabaseError::DomainNotFound, "Can't find domain: ")
         << domain;
}

template <typename T>
Expected<T, DatabaseError> InMemoryDatabase::getValue(const std::string& domain,
                                                      const std::string& key) {
  debug_only::verifyTrue(is_open_, "database is not open");
  if (!is_open_) {
    return createError(DatabaseError::DbIsNotOpen, "Database is closed");
  }
  auto storage_iter = storage_.find(domain);
  if (storage_iter == storage_.end()) {
    return domainNotFoundError(domain);
  }
  std::lock_guard<std::mutex> lock(storage_iter->second->getMutex());
  auto result = storage_iter->second->get(key);
  if (result) {
    DataType value = result.take();
    if (value.type() == typeid(T)) {
      return boost::get<T>(value);
    } else {
      auto error =
          createError(DatabaseError::KeyNotFound, "Requested wrong type for: ")
          << domain << ":" << key << " stored type: " << value.type().name()
          << " requested type " << boost::core::demangle(typeid(T).name());
      LOG(ERROR) << error.getFullMessageRecursive();
      debug_only::fail(error.getFullMessageRecursive().c_str());
      return std::move(error);
    }
  }
  return result.takeError();
}

template <typename T>
ExpectedSuccess<DatabaseError> InMemoryDatabase::putValue(
    const std::string& domain, const std::string& key, const T& value) {
  debug_only::verifyTrue(is_open_, "database is not open");
  if (!is_open_) {
    return createError(DatabaseError::DbIsNotOpen, "Database is closed");
  }
  auto storage_iter = storage_.find(domain);
  if (storage_iter == storage_.end()) {
    return domainNotFoundError(domain);
  }
  std::lock_guard<std::mutex> lock(storage_iter->second->getMutex());
  debug_only::verify(
      [&storage_iter, &key]() {
        auto result = storage_iter->second->get(key);
        return result && result.get().type() == typeid(T);
      },
      "changing type is not allowed");
  storage_iter->second->put(key, value);
  return Success();
}

Expected<std::string, DatabaseError> InMemoryDatabase::getString(
    const std::string& domain, const std::string& key) {
  return getValue<std::string>(domain, key);
}

ExpectedSuccess<DatabaseError> InMemoryDatabase::putString(
    const std::string& domain,
    const std::string& key,
    const std::string& value) {
  return putValue(domain, key, value);
}

Expected<int, DatabaseError> InMemoryDatabase::getInt32(
    const std::string& domain, const std::string& key) {
  return getValue<int32_t>(domain, key);
}

ExpectedSuccess<DatabaseError> InMemoryDatabase::putInt32(
    const std::string& domain, const std::string& key, const int32_t value) {
  return putValue(domain, key, value);
}

Expected<std::vector<std::string>, DatabaseError> InMemoryDatabase::getKeys(
    const std::string& domain, const std::string& prefix) {
  debug_only::verifyTrue(is_open_, "database is not open");
  auto storage_iter = storage_.find(domain);
  if (storage_iter == storage_.end()) {
    return domainNotFoundError(domain);
  }
  return storage_iter->second->getKeys(prefix);
}

ExpectedSuccess<DatabaseError> InMemoryDatabase::putStringsUnsafe(
    const std::string& domain,
    std::vector<std::pair<std::string, std::string>>& data) {
  debug_only::verifyTrue(is_open_, "database is not open");
  auto storage_iter = storage_.find(domain);
  if (storage_iter == storage_.end()) {
    return domainNotFoundError(domain);
  }
  std::lock_guard<std::mutex> lock(storage_iter->second->getMutex());
  for (const auto& pair : data) {
    storage_iter->second->put(pair.first, pair.second);
  }
  return Success();
}

} // namespace osquery
