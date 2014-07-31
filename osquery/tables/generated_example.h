// Copyright 2004-present Facebook. All Rights Reserved.

/*
** This file is generated. Do not modify it manually!
*/

#ifndef OSQUERY_TABLES_GENERATED_EXAMPLE_H
#define OSQUERY_TABLES_GENERATED_EXAMPLE_H

#include <string>
#include <vector>

#include "osquery/sqlite3.h"
#include "osquery/tables/base.h"

namespace osquery { namespace tables {

struct sqlite3_generated_example {
  int n;
  std::vector<std::string> name;
  std::vector<int> age;
  std::vector<std::string> gender;
};

extern const std::string
  sqlite3_generated_example_create_table_statement;

int sqlite3_generated_example_create(
  sqlite3 *db,
  const char *zName,
  sqlite3_generated_example **ppReturn
);

int generated_exampleCreate(
  sqlite3 *db,
  void *pAux,
  int argc,
  const char *const *argv,
  sqlite3_vtab **ppVtab,
  char **pzErr
);

int generated_exampleColumn(
  sqlite3_vtab_cursor *cur,
  sqlite3_context *ctx,
  int col
);

int generated_exampleFilter(
  sqlite3_vtab_cursor *pVtabCursor,
  int idxNum,
  const char *idxStr,
  int argc,
  sqlite3_value **argv
);

static sqlite3_module generated_exampleModule = {
  0,
  generated_exampleCreate,
  generated_exampleCreate,
  xBestIndex,
  xDestroy<x_vtab<sqlite3_generated_example>>,
  xDestroy<x_vtab<sqlite3_generated_example>>,
  xOpen<base_cursor>,
  xClose<base_cursor>,
  generated_exampleFilter,
  xNext<base_cursor>,
  xEof<base_cursor, x_vtab<sqlite3_generated_example>>,
  generated_exampleColumn,
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

#endif /* OSQUERY_TABLES_GENERATED_EXAMPLE_H */
