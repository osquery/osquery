// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/logger.h"
#include "osquery/core/virtual_table.h"

namespace osquery {
namespace tables {

std::string osquery_table::statement(TableName name,
                                     TableTypes types,
                                     TableColumns cols) {
  std::string statement = "CREATE TABLE " + name + "(";
  for (size_t i = 0; i < types.size(); ++i) {
    statement += cols[i] + " " + types[i];
    if (i < types.size() - 1) {
      statement += ", ";
    }
  }
  statement += ")";
  return statement;
}

void attachVirtualTables(sqlite3 *db) {
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
