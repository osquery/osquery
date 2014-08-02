// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/sqlite3.h"
#include "osquery/tables/base.h"
#include "osquery/tables/filesystem.h"
#include "osquery/tables/generated_example.h"
#include "osquery/tables/etc_hosts.h"
#include "osquery/tables/hash.h"

#include <iostream>
#include <map>
#include <string>

#include <glog/logging.h>

using namespace osquery::db;
using namespace osquery::tables;

namespace osquery { namespace core {

sqlite3_filesystem *fs_table;
sqlite3_hash *hash_table;

void sqlite3_attach_vtables(sqlite3 *db) {
  sqlite3_attach_vtable<sqlite3_generated_example>(db, "generated_example",
    &generated_exampleModule);
  sqlite3_attach_vtable<sqlite3_etc_hosts>(db, "etc_hosts",
    &etc_hostsModule);
  sqlite3_filesystem_create(db, "fs", &fs_table);
  sqlite3_hash_create(db, "hash", &hash_table);
}

sqlite3* createDB() {
  sqlite3* db = nullptr;
  sqlite3_open(":memory:", &db);
  sqlite3_attach_vtables(db);
  return db;
}

QueryData aggregateQuery(const std::string& q, int& error_return) {
  return aggregateQuery(q, error_return, createDB());
}

QueryData
aggregateQuery(const std::string& q, int& error_return, sqlite3* db) {
  QueryData d;
  char *err = nullptr;
  sqlite3_exec(db, q.c_str(), callback, &d, &err);
  if (err != nullptr) {
    LOG(ERROR) << "Error launching query: " << err;
    error_return = 1;
    sqlite3_free(err);
  } else {
    error_return = 0;
  }

  return d;
}

int callback(void* argument, int argc, char *argv[], char *column[]) {
  if (argument == nullptr) {
    LOG(ERROR) << "callback received nullptr as data argument";
    return SQLITE_MISUSE;
  }
  QueryData *qData = (QueryData*)argument;
  Row r;
  for (int i = 0; i < argc; i++) {
    r[column[i]] = argv[i];
  }
  (*qData).push_back(r);
  return 0;
}

}}
