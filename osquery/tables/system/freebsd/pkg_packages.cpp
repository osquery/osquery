/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/sql/sqlite_util.h"

#define DECLARE_TABLE_IMPLEMENTATION_pkg_packages
#include <generated/tables/tbl_pkg_packages_defs.hpp>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

const std::string kPkgDb = "/var/db/pkg/local.sqlite";

void genPkgRow(sqlite3_stmt* stmt, Row& r) {
  for (int i = 0; i < sqlite3_column_count(stmt); i++) {
    auto column_name = std::string(sqlite3_column_name(stmt, i));
    auto column_type = sqlite3_column_type(stmt, i);
    if (column_type == SQLITE_TEXT) {
      auto value = sqlite3_column_text(stmt, i);
      if (value != nullptr) {
        r[column_name] = std::string((const char*)value);
      }
    } else if (column_type == SQLITE_INTEGER) {
      auto value = sqlite3_column_int(stmt, i);
      r[column_name] = INTEGER(value);
    }
  }
}

QueryData genPkgPackages(QueryContext& context) {
  QueryData results;

  sqlite3* db = nullptr;

  auto rc = sqlite3_open_v2(
      kPkgDb.c_str(),
      &db,
      (SQLITE_OPEN_READONLY | SQLITE_OPEN_PRIVATECACHE | SQLITE_OPEN_NOMUTEX),
      nullptr);
  if (rc != SQLITE_OK || db == nullptr) {
    VLOG(1) << "Cannot open pkgdb: " << rc << " "
            << getStringForSQLiteReturnCode(rc);
    if (db != nullptr) {
      sqlite3_close(db);
    }
  }

  std::string query = "SELECT name, version, flatsize, arch FROM packages;";
  sqlite3_stmt* stmt = nullptr;
  rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
  while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
    Row r;

    genPkgRow(stmt, r);

    results.push_back(r);
  }

  // Clean up.
  sqlite3_finalize(stmt);
  sqlite3_close(db);

  return results;
}
}
}
