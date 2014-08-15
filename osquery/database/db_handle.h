// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef OSQUERY_DATABASE_DB_HANDLE_H
#define OSQUERY_DATABASE_DB_HANDLE_H

#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest_prod.h>
#include <rocksdb/db.h>

#include "osquery/status.h"

namespace osquery {
namespace db {

/////////////////////////////////////////////////////////////////////////////
// Constants
/////////////////////////////////////////////////////////////////////////////

// kDBPath represents the path of the RocksDB database on disk
extern const std::string kDBPath;

// kDomains is a const vector of required "domains", or "groups of keys"
extern const std::vector<std::string> kDomains;

// kQueries is the "domain" where query data, the results of queries, etc is
// stored.
extern const std::string kQueries;

// kConfigurations is the "domain" where  certain global configurations are
// stored
extern const std::string kConfigurations;

/////////////////////////////////////////////////////////////////////////////
// DBHandle is a RAII singleton around RocksDB database handles.
/////////////////////////////////////////////////////////////////////////////
class DBHandle {
public:
  // DBHandle's destructor takes care of deallocating all previously allocated
  // resources
  ~DBHandle();

  // getInstance returns a singleton instance of DBHandle.
  static std::shared_ptr<DBHandle> getInstance();

  /////////////////////////////////////////////////////////////////////////////
  // getters and setters
  /////////////////////////////////////////////////////////////////////////////

  // getStatus() returns the status_ property
  osquery::Status getStatus();

  // getDB() is a helper that's used to get access to db_
  rocksdb::DB *getDB();

  /////////////////////////////////////////////////////////////////////////////
  // Locking methods
  /////////////////////////////////////////////////////////////////////////////

  // if a set of operations needs to be atomic, use startTransaction() before
  // your operations and endTransaction() after your operations.
  void startTransaction();
  void endTransaction();

  /////////////////////////////////////////////////////////////////////////////
  // Data manipulation methods
  /////////////////////////////////////////////////////////////////////////////

  // Get a "key" from "domain" and store it's content in "value"
  osquery::Status Get(const std::string &domain, const std::string &key,
                      std::string &value);

  // Set "key" to "value" in "domain"
  osquery::Status Put(const std::string &domain, const std::string &key,
                      const std::string &value);

  // Delete "key" and it's corresponding value from "domain"
  osquery::Status Delete(const std::string &domain, const std::string &key);

  // List all keys in "domain" and store the results in "results"
  osquery::Status Scan(const std::string &domain,
                       std::vector<std::string> &results);

private:
  /////////////////////////////////////////////////////////////////////////////
  // Private methods
  /////////////////////////////////////////////////////////////////////////////

  // DBHandle's constructor takes care of properly connecting to RocksDB and
  // ensuring that all necessary column families are created. The resulting
  // database handle can then be accessed via getDB() and the success of the
  // connection can be determined by inspecting the resulting status code via
  // getStatus()
  DBHandle();
  DBHandle(std::string path, bool in_memory);

  // the private getInstance methods exist to expose a bit more of RocksDB's
  // functionality to DBHandle for use during unit tests
  static std::shared_ptr<DBHandle> getInstanceAtPath(const std::string &path);
  static std::shared_ptr<DBHandle> getInstanceInMemory();
  static std::shared_ptr<DBHandle> getInstance(const std::string &path,
                                               bool in_memory);

  /////////////////////////////////////////////////////////////////////////////
  // private getters and setters
  /////////////////////////////////////////////////////////////////////////////

  // getHandleForColumnFamily is a private helper around accessing the column
  // family handle for a specific column family, based on it's name
  rocksdb::ColumnFamilyHandle *getHandleForColumnFamily(const std::string &cf);

private:
  /////////////////////////////////////////////////////////////////////////////
  // Private members
  /////////////////////////////////////////////////////////////////////////////

  // db_ is the database handle
  rocksdb::DB *db_;

  // status_ is the status code that is generated during the attempt to connect
  // to RocksDB
  rocksdb::Status status_;

  // column_families_ is a vector of column family descriptors which are used
  // to connect to RocksDB
  std::vector<rocksdb::ColumnFamilyDescriptor> column_families_;

  // handles is a vector of pointers to column family handles
  std::vector<rocksdb::ColumnFamilyHandle *> handles_;

  // options_ contains the RocksDB database connection options that are used to
  // connect to RocksDB
  rocksdb::Options options_;

private:
  /////////////////////////////////////////////////////////////////////////////
  // Unit tests which can access private members
  /////////////////////////////////////////////////////////////////////////////

  FRIEND_TEST(DBHandleTests, test_create_new_database_on_disk);
  FRIEND_TEST(DBHandleTests, test_singleton_on_disk);
  FRIEND_TEST(DBHandleTests, test_get_instance_in_memory);
  FRIEND_TEST(DBHandleTests, test_is_query_name_in_database);
  FRIEND_TEST(DBHandleTests, test_get_handle_for_column_family);
  FRIEND_TEST(DBHandleTests, test_get_stored_query_names);
  FRIEND_TEST(DBHandleTests, test_get_executions);
  FRIEND_TEST(DBHandleTests, test_get);
  FRIEND_TEST(DBHandleTests, test_put);
  FRIEND_TEST(DBHandleTests, test_delete);
  FRIEND_TEST(DBHandleTests, test_scan);

  FRIEND_TEST(QueryTests, test_add_and_get_current_results);
  FRIEND_TEST(QueryTests, test_is_query_name_in_database);
  FRIEND_TEST(QueryTests, test_get_stored_query_names);
  FRIEND_TEST(QueryTests, test_get_executions);
  FRIEND_TEST(QueryTests, test_get_current_results);
  FRIEND_TEST(QueryTests, test_get_historical_query_results);
  FRIEND_TEST(QueryTests, test_query_name_not_found_in_db);
};
}
}

#endif /* OSQUERY_DATABASE_DB_HANDLE_H */
