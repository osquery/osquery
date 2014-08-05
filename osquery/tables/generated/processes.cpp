// Copyright 2004-present Facebook. All Rights Reserved.

/*
** This file is generated. Do not modify it manually!
*/

#include "osquery/tables/processes.h"
#include "osquery/tables/implementations/processes.h"

#include <string>
#include <vector>
#include <cstring>

#include <boost/lexical_cast.hpp>

#include "osquery/tables/base.h"

namespace osquery { namespace tables {

const std::string
  sqlite3_processes_create_table_statement =
  "CREATE TABLE processes("
    "name VARCHAR , "
    "path VARCHAR , "
    "pid  INTEGER, "
    "on_disk  INTEGER"
    ")";

int processesCreate(
  sqlite3 *db,
  void *pAux,
  int argc,
  const char *const *argv,
  sqlite3_vtab **ppVtab,
  char **pzErr
) {
  return xCreate<
    x_vtab<sqlite3_processes>,
    sqlite3_processes
  >(
    db, pAux, argc, argv, ppVtab, pzErr,
    sqlite3_processes_create_table_statement.c_str()
  );
}

int processesColumn(
  sqlite3_vtab_cursor *cur,
  sqlite3_context *ctx,
  int col
) {
  base_cursor *pCur = (base_cursor*)cur;
  x_vtab<sqlite3_processes> *pVtab =
    (x_vtab<sqlite3_processes>*)cur->pVtab;

  if(pCur->row >= 0 && pCur->row < pVtab->pContent->n) {
    switch (col) {
      // name
      case 0:
        sqlite3_result_text(
          ctx,
          (pVtab->pContent->name[pCur->row]).c_str(),
          -1,
          nullptr
        );
        break;
      // path
      case 1:
        sqlite3_result_text(
          ctx,
          (pVtab->pContent->path[pCur->row]).c_str(),
          -1,
          nullptr
        );
        break;
      // pid
      case 2:
        sqlite3_result_int(
          ctx,
          (int)pVtab->pContent->pid[pCur->row]
        );
        break;
      // on_disk
      case 3:
        sqlite3_result_int(
          ctx,
          (int)pVtab->pContent->on_disk[pCur->row]
        );
        break;
    }
  }
  return SQLITE_OK;
}

int processesFilter(
  sqlite3_vtab_cursor *pVtabCursor,
  int idxNum,
  const char *idxStr,
  int argc,
  sqlite3_value **argv
) {
  base_cursor *pCur = (base_cursor *)pVtabCursor;
  x_vtab<sqlite3_processes> *pVtab =
    (x_vtab<sqlite3_processes>*)pVtabCursor->pVtab;

  pCur->row = 0;
  pVtab->pContent->name = {};
  pVtab->pContent->path = {};
  pVtab->pContent->pid = {};
  pVtab->pContent->on_disk = {};

  for (auto& row : osquery::tables::genProcesses()) {
    pVtab->pContent->name.push_back(row["name"]);
    pVtab->pContent->path.push_back(row["path"]);
    pVtab->pContent->pid.push_back(boost::lexical_cast<int>(row["pid"]));
    pVtab->pContent->on_disk.push_back(boost::lexical_cast<int>(row["on_disk"]));
  }

  pVtab->pContent->n = pVtab->pContent->name.size();

  return SQLITE_OK;
}

}}
