/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <rocksdb/db.h>

#include <boost/noncopyable.hpp>

#include <osquery/core.h>
#include <osquery/flags.h>

namespace osquery {

DECLARE_string(database_path);

class DBHandle;
typedef std::shared_ptr<DBHandle> DBHandleRef;

/**
 * @brief RAII singleton around RocksDB database access.
 *
 * Accessing RocksDB necessitates creating several pointers which must be
 * carefully memory managed. DBHandle offers you a singleton which takes
 * care of acquiring and releasing the relevant pointers and data structures
 * for you.
 */
class DBHandle {
 public:
  /// Removes every column family handle and single DB handle/lock.
  ~DBHandle();

  /**
   * @brief The primary way to access the DBHandle singleton.
   *
   * DBHandle::getInstance() provides access to the DBHandle singleton.
   *
   * @code{.cpp}
   *   auto db = DBHandle::getInstance();
   *   std::string value;
   *   auto status = db->Get("default", "foo", value);
   *   if (status.ok()) {
   *     assert(value == "bar");
   *   }
   * @endcode
   *
   * @return a shared pointer to an instance of DBHandle
   */
  static DBHandleRef getInstance();

  /**
   * @brief Check the sanity of the database configuration options
   *
   * Create a handle to the backing store using the database configuration.
   * Catch any instance creation exceptions and release the handle immediately.
   *
   * @return Success if a handle was created without error.
   */
  static bool checkDB();

 private:
  /////////////////////////////////////////////////////////////////////////////
  // Data access methods
  /////////////////////////////////////////////////////////////////////////////

  /**
   * @brief Get data from the database
   *
   * @param domain the "domain" or "column family" that you'd like to retrieve
   * the data from
   * @param key the string key that you'd like to get
   * @param value a non-const string reference where the result of the
   * operation will be stored
   *
   * @return an instance of osquery::Status indicating the success or failure
   * of the operation.
   */
  Status Get(const std::string& domain,
             const std::string& key,
             std::string& value);

  /**
   * @brief Put data into the database
   *
   * @param domain the "domain" or "column family" that you'd like to insert
   * data into
   * @param key the string key that you'd like to put
   * @param value the data that you'd like to put into RocksDB
   *
   * @return an instance of osquery::Status indicating the success or failure
   * of the operation.
   */
  Status Put(const std::string& domain,
             const std::string& key,
             const std::string& value);

  /**
   * @brief Delete data from the database
   *
   * @param domain the "domain" or "column family" that you'd like to delete
   * data from
   * @param key the string key that you'd like to delete
   *
   * @return an instance of osquery::Status indicating the success or failure
   * of the operation.
   */
  Status Delete(const std::string& domain, const std::string& key);

  /**
   * @brief List the data in a "domain"
   *
   * @param domain the "domain" or "column family" that you'd like to list
   * data from
   * @param results a non-const reference to a vector which will be populated
   * with all of the keys from the supplied domain.
   *
   * @return an instance of osquery::Status indicating the success or failure
   * of the operation.
   */
  Status Scan(const std::string& domain, std::vector<std::string>& results);

 private:
  /**
   * @brief Default constructor
   *
   * DBHandle's constructor takes care of properly connecting to RocksDB and
   * ensuring that all necessary column families are created. The resulting
   * database handle can then be accessed via DBHandle::getDB() and the
   * success of the connection can be determined by inspecting the resulting
   * status code via DBHandle::getStatus()
   */
  DBHandle();

  /**
   * @brief Internal only constructor used to create instances of DBHandle.
   *
   * This constructor allows you to specify a few more details about how you'd
   * like DBHandle to be used. This is only used internally, so you should
   * never actually use it.
   *
   * @param path the path to create/access the database
   * @param in_memory a boolean indicating whether or not the database should
   * be creating in memory or not.
   */
  DBHandle(const std::string& path, bool in_memory);

  /**
   * @brief A method which allows you to override the database path
   *
   * This should only be used by unit tests. Never use it in production code.
   *
   * @return a shared pointer to an instance of DBHandle
   */
  static DBHandleRef getInstanceAtPath(const std::string& path);

  /**
   * @brief A method which gets you an in-memory RocksDB instance.
   *
   * This should only be used by unit tests. Never use it in production code.
   *
   * @return a shared pointer to an instance of DBHandle
   */
  static DBHandleRef getInstanceInMemory();

  /**
   * @brief A method which allows you to configure various aspects of RocksDB
   * database options.
   *
   * This should only be used by unit tests. Never use it in production code.
   *
   * @param path the path to create/access the database
   * @param in_memory a boolean indicating whether or not the database should
   * be creating in memory or not.
   *
   * @return a shared pointer to an instance of DBHandle
   */
  static DBHandleRef getInstance(const std::string& path, bool in_memory);

  /**
   * @brief Private helper around accessing the column family handle for a
   * specific column family, based on it's name
   */
  rocksdb::ColumnFamilyHandle* getHandleForColumnFamily(const std::string& cf);

  /**
   * @brief Helper method which can be used to get a raw pointer to the
   * underlying RocksDB database handle
   *
   * You probably shouldn't use this. DBHandle::getDB() should only be used
   * when you're positive that it's the right thing to use.
   *
   * @return a pointer to the underlying RocksDB database handle
   */
  rocksdb::DB* getDB();

 private:
  /////////////////////////////////////////////////////////////////////////////
  // Private members
  /////////////////////////////////////////////////////////////////////////////

  /// The database handle
  rocksdb::DB* db_{nullptr};

  /// Column family descriptors which are used to connect to RocksDB
  std::vector<rocksdb::ColumnFamilyDescriptor> column_families_;

  /// A vector of pointers to column family handles
  std::vector<rocksdb::ColumnFamilyHandle*> handles_;

  /// The RocksDB connection options that are used to connect to RocksDB
  rocksdb::Options options_;

  /// The database was opened in a ReadOnly mode.
  bool read_only_{false};

 private:
  friend class RocksDatabasePlugin;
  friend class Query;
  friend class EventSubscriberPlugin;

  /////////////////////////////////////////////////////////////////////////////
  // Unit tests which can access private members
  /////////////////////////////////////////////////////////////////////////////

  friend class DBHandleTests;
  FRIEND_TEST(DBHandleTests, test_get);
  FRIEND_TEST(DBHandleTests, test_put);
  FRIEND_TEST(DBHandleTests, test_delete);
  FRIEND_TEST(DBHandleTests, test_scan);
  friend class QueryTests;
  FRIEND_TEST(QueryTests, test_get_query_results);
  FRIEND_TEST(QueryTests, test_is_query_name_in_database);
  FRIEND_TEST(QueryTests, test_get_stored_query_names);
  friend class EventsTests;
  friend class EventsDatabaseTests;
};
}
