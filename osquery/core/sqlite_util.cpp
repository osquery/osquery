/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/sqlite_util.h"
#include "osquery/core/virtual_table.h"

namespace osquery {

sqlite3* createDB() {
  sqlite3* db = nullptr;
  sqlite3_open(":memory:", &db);
  osquery::tables::attachVirtualTables(db);
  return db;
}

QueryData query(const std::string& q, int& error_return) {
  sqlite3* db = createDB();
  QueryData results = query(q, error_return, db);
  sqlite3_close(db);
  return results;
}

QueryData query(const std::string& q, int& error_return, sqlite3* db) {
  QueryData d;
  char* err = nullptr;
  sqlite3_exec(db, q.c_str(), query_data_callback, &d, &err);
  if (err != nullptr) {
    LOG(ERROR) << "Error launching query: " << err;
    error_return = 1;
    sqlite3_free(err);
  } else {
    error_return = 0;
  }

  return d;
}

int query_data_callback(void* argument,
                        int argc,
                        char* argv[],
                        char* column[]) {
  if (argument == nullptr) {
    LOG(ERROR) << "query_data_callback received nullptr as data argument";
    return SQLITE_MISUSE;
  }
  QueryData* qData = (QueryData*)argument;
  Row r;
  for (int i = 0; i < argc; i++) {
    r[column[i]] = argv[i];
  }
  (*qData).push_back(r);
  return 0;
}
}
