// Copyright 2004-present Facebook. All Rights Reserved.

/*
** This file is generated. Do not modify it manually!
*/

#include "osquery/tables/generated_example.h"
#include "osquery/tables/implementations/example.h"

#include <string>
#include <vector>
#include <cstring>

#include <boost/lexical_cast.hpp>

#include "osquery/tables/base.h"

namespace osquery { namespace tables {

const std::string
  sqlite3_generated_example_create_table_statement =
  "CREATE TABLE generated_example("
    "name VARCHAR , "
    "age  INTEGER, "
    "gender VARCHAR "
    ")";

int generated_exampleCreate(
  sqlite3 *db,
  void *pAux,
  int argc,
  const char *const *argv,
  sqlite3_vtab **ppVtab,
  char **pzErr
) {
  return xCreate<
    x_vtab<sqlite3_generated_example>,
    sqlite3_generated_example
  >(
    db, pAux, argc, argv, ppVtab, pzErr,
    sqlite3_generated_example_create_table_statement.c_str()
  );
}

int generated_exampleColumn(
  sqlite3_vtab_cursor *cur,
  sqlite3_context *ctx,
  int col
) {
  base_cursor *pCur = (base_cursor*)cur;
  x_vtab<sqlite3_generated_example> *pVtab =
    (x_vtab<sqlite3_generated_example>*)cur->pVtab;

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
      // age
      case 1:
        sqlite3_result_int(
          ctx,
          (int)pVtab->pContent->age[pCur->row]
        );
        break;
      // gender
      case 2:
        sqlite3_result_text(
          ctx,
          (pVtab->pContent->gender[pCur->row]).c_str(),
          -1,
          nullptr
        );
        break;
    }
  }
  return SQLITE_OK;
}

int generated_exampleFilter(
  sqlite3_vtab_cursor *pVtabCursor,
  int idxNum,
  const char *idxStr,
  int argc,
  sqlite3_value **argv
) {
  base_cursor *pCur = (base_cursor *)pVtabCursor;
  x_vtab<sqlite3_generated_example> *pVtab =
    (x_vtab<sqlite3_generated_example>*)pVtabCursor->pVtab;

  pCur->row = 0;

  for (auto& row : osquery::tables::genExample()) {
    pVtab->pContent->name.push_back(row["name"]);
    pVtab->pContent->age.push_back(boost::lexical_cast<int>(row["age"]));
    pVtab->pContent->gender.push_back(row["gender"]);
  }

  pVtab->pContent->n = pVtab->pContent->name.size();

  return SQLITE_OK;
}

}}
