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

#include <boost/variant.hpp>
#include <unordered_map>

#include <osquery/core/database/database.h>

namespace osquery {

template <typename StorageType>
class InMemoryStorage final {
 public:
  void put(const std::string& key, const StorageType value);
  Expected<StorageType, DatabaseError> get(const std::string& key) const;
  std::vector<std::string> getKeys(const std::string& prefix = "") const;

  std::mutex& getMutex() {
    return mutex_;
  }

 private:
  std::unordered_map<std::string, StorageType> storage_;
  std::mutex mutex_;
};

class InMemoryDatabase final : public Database {
 public:
  explicit InMemoryDatabase(std::string name) : Database(std::move(name)){};
  ~InMemoryDatabase() override {}

  ExpectedSuccess<DatabaseError> destroyDB() override;
  ExpectedSuccess<DatabaseError> open() override;

  void close() override;

  Expected<int32_t, DatabaseError> getInt32(const std::string& domain,
                                            const std::string& key) override;
  Expected<std::string, DatabaseError> getString(
      const std::string& domain, const std::string& key) override;

  ExpectedSuccess<DatabaseError> putInt32(const std::string& domain,
                                          const std::string& key,
                                          const int32_t value) override;
  ExpectedSuccess<DatabaseError> putString(const std::string& domain,
                                           const std::string& key,
                                           const std::string& value) override;

  Expected<std::vector<std::string>, DatabaseError> getKeys(
      const std::string& domain, const std::string& prefix = "") override;

  // This method bypass type validation and will silently update value
  // even if type was changed (e.g int->string)
  ExpectedSuccess<DatabaseError> putStringsUnsafe(
      const std::string& domain,
      std::vector<std::pair<std::string, std::string>>& data) override;

 private:
  template <typename T>
  Expected<T, DatabaseError> getValue(const std::string& domain,
                                      const std::string& key);
  template <typename T>
  ExpectedSuccess<DatabaseError> putValue(const std::string& domain,
                                          const std::string& key,
                                          const T& value);

  Error<DatabaseError> domainNotFoundError(const std::string& domain) const;

 private:
  bool is_open_ = false;

  using DataType = boost::variant<std::string, int32_t>;
  using InMemoryStorageRef = std::unique_ptr<InMemoryStorage<DataType>>;

  // storage map is built on open, so no need to protect it with locks
  std::unordered_map<std::string, InMemoryStorageRef> storage_;
};

} // namespace osquery
