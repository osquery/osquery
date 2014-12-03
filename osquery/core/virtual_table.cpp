// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/logger.h"
#include "osquery/core/virtual_table.h"

namespace osquery {
namespace tables {

int xOpen(sqlite3_vtab *pVTab, sqlite3_vtab_cursor **ppCursor) {
  int rc = SQLITE_NOMEM;
  base_cursor *pCur;

  pCur = new base_cursor;

  if (pCur) {
    memset(pCur, 0, sizeof(base_cursor));
    *ppCursor = (sqlite3_vtab_cursor *)pCur;
    rc = SQLITE_OK;
  }

  return rc;
}

int xClose(sqlite3_vtab_cursor *cur) {
  base_cursor *pCur = (base_cursor *)cur;

  delete pCur;
  return SQLITE_OK;
}

int xNext(sqlite3_vtab_cursor *cur) {
  base_cursor *pCur = (base_cursor *)cur;
  pCur->row++;
  return SQLITE_OK;
}

int xRowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid) {
  base_cursor *pCur = (base_cursor *)cur;
  *pRowid = pCur->row;
  return SQLITE_OK;
}

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
