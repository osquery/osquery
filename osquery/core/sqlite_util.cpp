// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"
#include "osquery/core/sqlite_util.h"

#include <iostream>
#include <map>
#include <string>

#include <glog/logging.h>
#include <sqlite3.h>

#include "osquery/database.h"
#include "osquery/tables/base.h"
#include "osquery/registry/registry.h"

using namespace osquery::tables;

namespace osquery {

sqlite3* createDB() {
  sqlite3* db = openDB(":memory:");
  osquery::tables::attachVirtualTables(db);
  return db;
}

sqlite3* openDB(const std::string& file_name) {
  sqlite3* db = nullptr;
  sqlite3_open(file_name.c_str(), &db);
  return db;
}

int closeDB(sqlite3* db) { return sqlite3_close(db); }

QueryData query(const std::string& q, int& error_return) {
  sqlite3* db = createDB();
  QueryData results = query(q, error_return, db);
  sqlite3_close(db);
  return results;
}

QueryData query(const std::string& q, int& error_return, sqlite3* db) {
  QueryData d;
  char* err = nullptr;
  sqlite3_exec(db, q.c_str(), core::query_data_callback, &d, &err);
  if (err != nullptr) {
    LOG(ERROR) << "Error launching query: " << err;
    error_return = 1;
    sqlite3_free(err);
  } else {
    error_return = 0;
  }

  return d;
}

namespace core {

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
}
