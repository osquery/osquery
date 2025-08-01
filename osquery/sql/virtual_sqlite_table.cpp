/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string.hpp>

#include <osquery/core/core.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/utils/scope_guard.h>

#include <osquery/utils/info/platform_type.h>

#include "osquery/sql/dynamic_table_row.h"
#include "osquery/sql/sqlite_util.h"

namespace fs = boost::filesystem;

namespace osquery {

const char* getSystemVFS(bool respect_locking) {
  if (respect_locking) {
    return nullptr;
  }
  if (isPlatform(PlatformType::TYPE_POSIX)) {
    return "unix-none";
  } else if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    return "win32-none";
  }
  return nullptr;
}

Status genSqliteTableRow(sqlite3_stmt* stmt,
                         TableRows& qd,
                         const fs::path& sqlite_db) {
  bool user_defined_path_column = false;
  auto r = make_table_row();
  for (int i = 0; i < sqlite3_column_count(stmt); ++i) {
    auto column_name = std::string(sqlite3_column_name(stmt, i));
    auto column_type = sqlite3_column_type(stmt, i);

    if (boost::iequals(column_name, "path")) {
      user_defined_path_column = true;
    }

    switch (column_type) {
    case SQLITE_BLOB:
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
      auto int_value = sqlite3_column_int64(stmt, i);
      r[column_name] = INTEGER(int_value);
      break;
    }
    }
  }
  if (user_defined_path_column) {
    LOG(WARNING) << "ATC Table: Row contains a defined path key, omitting the "
                    "implicit one";
  } else {
    r["path"] = sqlite_db.string();
  }
  qd.push_back(std::move(r));
  return Status::success();
}

Status genTableRowsForSqliteTable(const fs::path& sqlite_db,
                                  const std::string& sqlite_query,
                                  TableRows& results,
                                  bool respect_locking) {
  if (!pathExists(sqlite_db).ok()) {
    return Status(1, "Database path does not exist");
  }

  sqlite3* db = nullptr;
  auto db_guard = scope_guard::create([&db]() { sqlite3_close(db); });

  int rc = sqlite3_open_v2(
      sqlite_db.string().c_str(),
      &db,
      (SQLITE_OPEN_READONLY | SQLITE_OPEN_PRIVATECACHE | SQLITE_OPEN_NOMUTEX),
      getSystemVFS(respect_locking));
  if (rc != SQLITE_OK || db == nullptr) {
    VLOG(1) << "Cannot open specified database: "
            << getStringForSQLiteReturnCode(rc);
    return Status(1, "Could not open database");
  }

  rc = sqlite3_set_authorizer(db, &sqliteAuthorizer, nullptr);
  if (rc != SQLITE_OK) {
    auto errMsg =
        std::string("Failed to set sqlite authorizer: ") + sqlite3_errmsg(db);
    return Status(1, errMsg);
  }

  sqlite3_stmt* stmt = nullptr;
  auto stmt_guard = scope_guard::create([&stmt]() { sqlite3_finalize(stmt); });

  rc = sqlite3_prepare_v2(db, sqlite_query.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    VLOG(1) << "ATC table: Could not prepare database at path: " << sqlite_db
            << " error code: " << rc << ". Retrying with immutable=1";

    // Close the previous connection, which won't be closed by the guard.
    sqlite3_close(db);

    // Reopen the database with the immutable=1 flag. This was found to work on
    // databases that are currently in use by a Firefox profile when the regular
    // open throws an error 5 or error 14. We aren't doing this by default
    // because there may be unintended consequences. The docs say if the file
    // changes, "SQLite might return incorrect query results and/or
    // SQLITE_CORRUPT errors."
    std::string sqlite_string = "file:" + sqlite_db.string() + "?immutable=1";
    auto rc = sqlite3_open_v2(sqlite_string.c_str(),
                              &db,
                              (SQLITE_OPEN_READONLY | SQLITE_OPEN_PRIVATECACHE |
                               SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_URI),
                              getSystemVFS(respect_locking));
    if (rc != SQLITE_OK || db == nullptr) {
      VLOG(1) << "Cannot open specified database even with immutable=1: "
              << getStringForSQLiteReturnCode(rc);
      return Status(1, "Could not open database");
    }

    rc = sqlite3_set_authorizer(db, &sqliteAuthorizer, nullptr);
    if (rc != SQLITE_OK) {
      auto errMsg =
          std::string("Failed to set sqlite authorizer: ") + sqlite3_errmsg(db);
      return Status(1, errMsg);
    }

    rc = sqlite3_prepare_v2(db, sqlite_query.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
      VLOG(1) << "ATC table: Could not prepare database at path: " << sqlite_db
              << " error code: " << rc << ". Even with immutable=1";

      return Status(rc, "Could not prepare database");
    }
  }

  while ((sqlite3_step(stmt)) == SQLITE_ROW) {
    auto s = genSqliteTableRow(stmt, results, sqlite_db);
    if (!s.ok()) {
      return s;
    }
  }

  return Status::success();
}

Status getSqliteJournalMode(const fs::path& sqlite_db) {
  TableRows result;
  auto status = genTableRowsForSqliteTable(
      sqlite_db, "PRAGMA journal_mode;", result, true);
  if (!status.ok()) {
    return status;
  }
  if (result.empty()) {
    VLOG(1) << "PRAGMA query returned empty results";
    return Status(1, "Could not retrieve journal mode");
  }
  auto resultmap = static_cast<Row>(*result[0]);
  if (resultmap.find("journal_mode") == resultmap.end()) {
    VLOG(1) << "journal_mode not found PRAGMA query results";
    return Status(1, "Could not retrieve journal mode");
  }
  return Status(Status::kSuccessCode,
                boost::algorithm::to_lower_copy(resultmap["journal_mode"]));
}

} // namespace osquery
