// Copyright 2004-present Facebook. All Rights Reserved.

/*
** This file is generated. Do not modify it manually!
*/

#include "osquery/tables/etc_hosts.h"
#include "osquery/tables/implementations/etc_hosts.h"

#include <string>
#include <vector>
#include <cstring>

#include <boost/lexical_cast.hpp>

#include "osquery/tables/base.h"

namespace osquery { namespace tables {

const std::string
  sqlite3_etc_hosts_create_table_statement =
  "CREATE TABLE etc_hosts("
    "address VARCHAR , "
    "hostnames VARCHAR "
    ")";

int etc_hostsCreate(
  sqlite3 *db,
  void *pAux,
  int argc,
  const char *const *argv,
  sqlite3_vtab **ppVtab,
  char **pzErr
) {
  return xCreate<
    x_vtab<sqlite3_etc_hosts>,
    sqlite3_etc_hosts
  >(
    db, pAux, argc, argv, ppVtab, pzErr,
    sqlite3_etc_hosts_create_table_statement.c_str()
  );
}

int etc_hostsColumn(
  sqlite3_vtab_cursor *cur,
  sqlite3_context *ctx,
  int col
) {
  base_cursor *pCur = (base_cursor*)cur;
  x_vtab<sqlite3_etc_hosts> *pVtab =
    (x_vtab<sqlite3_etc_hosts>*)cur->pVtab;

  if(pCur->row >= 0 && pCur->row < pVtab->pContent->n) {
    switch (col) {
      // address
      case 0:
        sqlite3_result_text(
          ctx,
          (pVtab->pContent->address[pCur->row]).c_str(),
          -1,
          nullptr
        );
        break;
      // hostnames
      case 1:
        sqlite3_result_text(
          ctx,
          (pVtab->pContent->hostnames[pCur->row]).c_str(),
          -1,
          nullptr
        );
        break;
    }
  }
  return SQLITE_OK;
}

int etc_hostsFilter(
  sqlite3_vtab_cursor *pVtabCursor,
  int idxNum,
  const char *idxStr,
  int argc,
  sqlite3_value **argv
) {
  base_cursor *pCur = (base_cursor *)pVtabCursor;
  x_vtab<sqlite3_etc_hosts> *pVtab =
    (x_vtab<sqlite3_etc_hosts>*)pVtabCursor->pVtab;

  pCur->row = 0;

  for (auto& row : osquery::tables::genEtcHosts()) {
    pVtab->pContent->address.push_back(row["address"]);
    pVtab->pContent->hostnames.push_back(row["hostnames"]);
  }

  pVtab->pContent->n = pVtab->pContent->address.size();

  return SQLITE_OK;
}

}}
