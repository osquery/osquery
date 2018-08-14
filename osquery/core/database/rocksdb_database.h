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

#include <unordered_map>

#include <boost/filesystem.hpp>
#include <rocksdb/db.h>

#include <osquery/core/database/database.h>
#include <osquery/database/plugins/rocksdb.h>

namespace osquery {

enum class RocksdbError {
  UnexpectedValueType = 1,
  DatabaseIsCorrupted = 2,
  BatchWriteFail = 3,
};

class RocksdbDatabase final : public Database {
 public:
  using Handle = rocksdb::ColumnFamilyHandle;
  using HandleRef = std::shared_ptr<Handle>;

  RocksdbDatabase(std::string name) = delete;
  explicit RocksdbDatabase(std::string name, std::string path)
      : Database(std::move(name)), path_(std::move(path)){};
  ~RocksdbDatabase() override {}

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

  // This function should be used only as optimization
  // This write operation will not use neither sync or WAL, so date lose
  // may happen in case of failure, but opertaion itself is still atomic
  ExpectedSuccess<DatabaseError> putStringsUnsafe(
      const std::string& domain,
      std::vector<std::pair<std::string, std::string>>& data) override;

 private:
  rocksdb::Options getOptions();
  std::vector<rocksdb::ColumnFamilyDescriptor> createDefaultColumnFamilies(
      const rocksdb::Options& options);
  ExpectedSuccess<DatabaseError> openInternal(
      const rocksdb::Options& options, const boost::filesystem::path& path);
  Expected<std::string, DatabaseError> getRawBytesInternal(
      Handle* handle, const std::string& key);
  ExpectedSuccess<DatabaseError> putRawBytesInternal(Handle* handle,
                                                     const std::string& key,
                                                     const std::string& value);
  ExpectedSuccess<DatabaseError> checkDbConnection();
  Expected<std::shared_ptr<Handle>, DatabaseError> getHandle(
      const std::string& domain);

  Expected<std::string, DatabaseError> getRawBytes(const std::string& domain,
                                                   const std::string& key);
  ExpectedSuccess<DatabaseError> putRawBytes(const std::string& domain,
                                             const std::string& key,
                                             const std::string& value);

 private:
  bool in_panic_ = false;
  rocksdb::ReadOptions default_read_options_;
  rocksdb::WriteOptions default_write_options_;
  rocksdb::WriteOptions batch_write_options_;
  std::unique_ptr<rocksdb::DB> db_ = nullptr;

  std::string path_;
  std::unordered_map<std::string, HandleRef> handles_map_;
};

} // namespace osquery
