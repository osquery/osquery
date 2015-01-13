/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/logger.h>

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

int xEof(sqlite3_vtab_cursor *cur) {
  base_cursor *pCur = (base_cursor *)cur;
  auto *pVtab = (x_vtab<TablePlugin> *)cur->pVtab;
  return pCur->row >= pVtab->pContent->n;
}

int xDestroy(sqlite3_vtab *p) {
  auto *pVtab = (x_vtab<TablePlugin> *)p;
  delete pVtab->pContent;
  delete pVtab;
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

std::string TablePlugin::statement(TableName name, TableColumns columns) {
  std::string statement = "CREATE TABLE " + name + "(";
  for (size_t i = 0; i < columns.size(); ++i) {
    statement += columns[i].first + " " + columns[i].second;
    if (i < columns.size() - 1) {
      statement += ", ";
    }
  }
  statement += ")";
  return statement;
}

void attachVirtualTables(sqlite3 *db) {
  for (const auto &table : REGISTERED_TABLES) {
    int s = table.second->attachVtable(db);
    if (s != SQLITE_OK) {
      LOG(ERROR) << "Error attaching virtual table: " << table.first << " ("
                 << s << ")";
    }
  }
}
}
}
