// Copyright 2004-present Facebook. All Rights Reserved.

/*
** This file is generated. Do not modify it manually!
*/

#ifndef OSQUERY_TABLES_PROCESSES_H
#define OSQUERY_TABLES_PROCESSES_H

#include <string>
#include <vector>

#include "osquery/sqlite3.h"
#include "osquery/tables/base.h"

namespace osquery { namespace tables {

struct sqlite3_processes {
  int n;
  std::vector<std::string> name;
  std::vector<std::string> path;
  std::vector<int> pid;
  std::vector<int> on_disk;
  std::vector<std::string> wired_size;
  std::vector<std::string> resident_size;
  std::vector<std::string> phys_footprint;
  std::vector<std::string> user_time;
  std::vector<std::string> system_time;
  std::vector<std::string> start_time;
  std::vector<int> parent;
};

extern const std::string
  sqlite3_processes_create_table_statement;

int sqlite3_processes_create(
  sqlite3 *db,
  const char *zName,
  sqlite3_processes **ppReturn
);

int processesCreate(
  sqlite3 *db,
  void *pAux,
  int argc,
  const char *const *argv,
  sqlite3_vtab **ppVtab,
  char **pzErr
);

int processesColumn(
  sqlite3_vtab_cursor *cur,
  sqlite3_context *ctx,
  int col
);

int processesFilter(
  sqlite3_vtab_cursor *pVtabCursor,
  int idxNum,
  const char *idxStr,
  int argc,
  sqlite3_value **argv
);

static sqlite3_module processesModule = {
  0,
  processesCreate,
  processesCreate,
  xBestIndex,
  xDestroy<x_vtab<sqlite3_processes>>,
  xDestroy<x_vtab<sqlite3_processes>>,
  xOpen<base_cursor>,
  xClose<base_cursor>,
  processesFilter,
  xNext<base_cursor>,
  xEof<base_cursor, x_vtab<sqlite3_processes>>,
  processesColumn,
  xRowid<base_cursor>,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
};

}}

#endif /* OSQUERY_TABLES_PROCESSES_H */
