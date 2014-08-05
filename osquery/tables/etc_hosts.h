// Copyright 2004-present Facebook. All Rights Reserved.

/*
** This file is generated. Do not modify it manually!
*/

#ifndef OSQUERY_TABLES_ETC_HOSTS_H
#define OSQUERY_TABLES_ETC_HOSTS_H

#include <string>
#include <vector>

#include "osquery/sqlite3.h"
#include "osquery/tables/base.h"

namespace osquery { namespace tables {

struct sqlite3_etc_hosts {
  int n;
  std::vector<std::string> address;
  std::vector<std::string> hostnames;
};

extern const std::string
  sqlite3_etc_hosts_create_table_statement;

int sqlite3_etc_hosts_create(
  sqlite3 *db,
  const char *zName,
  sqlite3_etc_hosts **ppReturn
);

int etc_hostsCreate(
  sqlite3 *db,
  void *pAux,
  int argc,
  const char *const *argv,
  sqlite3_vtab **ppVtab,
  char **pzErr
);

int etc_hostsColumn(
  sqlite3_vtab_cursor *cur,
  sqlite3_context *ctx,
  int col
);

int etc_hostsFilter(
  sqlite3_vtab_cursor *pVtabCursor,
  int idxNum,
  const char *idxStr,
  int argc,
  sqlite3_value **argv
);

static sqlite3_module etc_hostsModule = {
  0,
  etc_hostsCreate,
  etc_hostsCreate,
  xBestIndex,
  xDestroy<x_vtab<sqlite3_etc_hosts>>,
  xDestroy<x_vtab<sqlite3_etc_hosts>>,
  xOpen<base_cursor>,
  xClose<base_cursor>,
  etc_hostsFilter,
  xNext<base_cursor>,
  xEof<base_cursor, x_vtab<sqlite3_etc_hosts>>,
  etc_hostsColumn,
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

#endif /* OSQUERY_TABLES_ETC_HOSTS_H */
