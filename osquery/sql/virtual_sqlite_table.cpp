/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/sql/sqlite_util.h"

namespace fs = boost::filesystem;

namespace osquery {

Status genSqliteQueryRow(sqlite3_stmt* stmt,
                         QueryData& qd,
                         const fs::path& sqlite_db) {
  Row r;
  for (auto i{0}; i < sqlite3_column_count(stmt); ++i) {
    auto column_name = std::string(sqlite3_column_name(stmt, i));
    auto column_type = sqlite3_column_type(stmt, i);
    switch (column_type) {
    case SQLITE_TEXT: {
      auto text_value = sqlite3_column_text(stmt, i);
      if (text_value != nullptr) {
        r[column_name] = std::string(reinterpret_cast<const char*>(text_value));
      }
      break;
    }
    case SQLITE_FLOAT: {
      auto float_value = sqlite3_column_double(stmt, i);
      r[column_name] = DOUBLE(float_value);
      break;
    }
    case SQLITE_INTEGER: {
      auto int_value = sqlite3_column_int(stmt, i);
      r[column_name] = INTEGER(int_value);
      break;
    }
    }
  }
  if (r.count("path") > 0) {
    LOG(WARNING) << "Row contains a path key, refusing to overwrite";
  } else {
    r["path"] = sqlite_db.string();
  }
  qd.push_back(r);
  return Status{};
}

Status genQueryDataForSqliteTable(const fs::path& sqlite_db,
                                  const std::string& sqlite_query,
                                  QueryData& results) {
  sqlite3* db = nullptr;
  if (!pathExists(sqlite_db).ok()) {
    return Status(1, "Database path does not exist");
  }

  auto rc = sqlite3_open_v2(
      sqlite_db.c_str(),
      &db,
      (SQLITE_OPEN_READONLY | SQLITE_OPEN_PRIVATECACHE | SQLITE_OPEN_NOMUTEX),
      nullptr);
  if (rc != SQLITE_OK || db == nullptr) {
    VLOG(1) << "Cannot open specified database: "
            << getStringForSQLiteReturnCode(rc);
    if (db != nullptr) {
      sqlite3_close(db);
    }
    return Status(1, "Could not open database");
  }

  sqlite3_stmt* stmt = nullptr;
  rc = sqlite3_prepare_v2(db, sqlite_query.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    sqlite3_close(db);
    VLOG(1) << "Could not prepare database at path: " << sqlite_db;
    return Status(rc, "Could not prepare database");
  }

  while ((sqlite3_step(stmt)) == SQLITE_ROW) {
    auto s = genSqliteQueryRow(stmt, results, sqlite_db);
    if (!s.ok()) {
      break;
    }
  }

  // Clean up.
  sqlite3_finalize(stmt);
  sqlite3_close(db);

  return Status{};
}
} // namespace osquery
