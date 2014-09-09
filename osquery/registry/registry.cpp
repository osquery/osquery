// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/registry/registry.h"

#include <glog/logging.h>

//#include "osquery/tables/manual/filesystem.h"
//#include "osquery/tables/manual/hash.h"

namespace osquery {
namespace tables {

// sqlite3_filesystem *fs_table;
// sqlite3_hash *hash_table;

void attachVirtualTables(sqlite3 *db) {
  // sqlite3_filesystem_create(db, "fs", &fs_table);
  // sqlite3_hash_create(db, "hash", &hash_table);
  for (const auto &table : REGISTERED_TABLES) {
    VLOG(1) << "Attaching virtual table: " << table.first;
    int s = table.second->attachVtable(db);
    if (s != SQLITE_OK) {
      LOG(ERROR) << "Error attaching virtual table: " << table.first << " ("
                 << s << ")";
    }
  }
}
}
}
