/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <atomic>

#include <rocksdb/db.h>

#include <osquery/core/core.h>
#include <osquery/database/database.h>
#include <osquery/utils/mutex.h>

#include <gtest/gtest_prod.h>

namespace osquery {

/**
 * @brief This class is used to capture internal RocksDB messages.
 *
 * This can capture internal RocksDB warnings and errors.
 * We can use them to check the status of the database and forward to the logger
 * plugin so they are not lost to stderr.
 */
class GlogRocksDBLogger : public rocksdb::Logger {
 public:
  using rocksdb::Logger::Logv;

  /// Capture log events from RocksDB, inspect, and potentially forward to Glog.
  void Logv(const char* format, va_list ap) override;
};

class RocksDBDatabasePlugin : public DatabasePlugin {
 public:
  /// Data retrieval method.
  Status get(const std::string& domain,
             const std::string& key,
             std::string& value) const override;

  Status get(const std::string& domain,
             const std::string& key,
             int& value) const override;

  /// Data storage method.
  Status put(const std::string& domain,
             const std::string& key,
             const std::string& value) override;

  Status put(const std::string& domain,
             const std::string& key,
             int value) override;

  Status putBatch(const std::string& domain,
                  const DatabaseStringValueList& data) override;

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
              uint64_t max) const override;

 public:
  /// Database workflow: open and setup.
  Status setUp() override;

  /// Database workflow: close and cleanup.
  void tearDown() override;

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

  /// Request RocksDB compact each domain and level to that same level.
  Status compactFiles(const std::string& domain);

  /**
   * @brief Helper method to repair a corrupted db. Best effort only.
   *
   * @return nothing.
   */
  void repairDB();

  /// Flush memtables and trigger compaction.
  void flush();

 private:
  /**
   * @brief Mark the RocksDB database as corrupted.
   *
   * This will set the global kCorruptionIndicator.
   * This may be used from tests or from the RocksDB logger.
   */
  static void setCorrupted(bool corrupted = true);

  /// Check if the RocksDB database as been marked corrupted.
  static bool isCorrupted();

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

 private:
  friend class GlogRocksDBLogger;
  FRIEND_TEST(RocksDBDatabasePluginTests, test_corruption);
};
} // namespace osquery
