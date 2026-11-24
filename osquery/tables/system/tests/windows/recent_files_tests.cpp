/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <sqlite3.h>

#include <string>

namespace osquery {
namespace tables {

std::string getRecentFilesQuery(const std::string& user_path_prefix);

namespace {

const std::string kRecentSuffix =
    "\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\document.lnk";

// Runs the generated query against an in-memory stand-in for the file table
// holding one shortcut at lnk_path. Returns the number of rows the query
// produces, or -1 if it does not prepare.
int countRecentFileRows(const std::string& query, const std::string& lnk_path) {
  sqlite3* db = nullptr;
  if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
    sqlite3_close(db);
    return -1;
  }

  const char* schema =
      "CREATE TABLE file(filename TEXT, path TEXT, mtime INTEGER, "
      "shortcut_target_path TEXT, shortcut_target_type TEXT);";
  sqlite3_stmt* insert = nullptr;
  if (sqlite3_exec(db, schema, nullptr, nullptr, nullptr) != SQLITE_OK ||
      sqlite3_prepare_v2(db,
                         "INSERT INTO file VALUES ('document.lnk', ?, 1, "
                         "'C:\\Temp\\document.txt', 'Text Document');",
                         -1,
                         &insert,
                         nullptr) != SQLITE_OK) {
    sqlite3_finalize(insert);
    sqlite3_close(db);
    return -1;
  }
  sqlite3_bind_text(insert, 1, lnk_path.c_str(), -1, SQLITE_TRANSIENT);
  auto rc = sqlite3_step(insert);
  sqlite3_finalize(insert);
  if (rc != SQLITE_DONE) {
    sqlite3_close(db);
    return -1;
  }

  sqlite3_stmt* stmt = nullptr;
  if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return -1;
  }

  int rows = 0;
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    ++rows;
  }
  sqlite3_finalize(stmt);
  sqlite3_close(db);
  return rows;
}

} // namespace

TEST(RecentFilesTests, test_query_matches_profile_path) {
  const std::string prefix = "C:\\Users\\osquery";
  EXPECT_EQ(
      countRecentFileRows(getRecentFilesQuery(prefix), prefix + kRecentSuffix),
      1);
}

TEST(RecentFilesTests, test_query_with_quote_in_profile_path) {
  const std::string prefix = "C:\\Users\\O'Brien";
  EXPECT_EQ(
      countRecentFileRows(getRecentFilesQuery(prefix), prefix + kRecentSuffix),
      1);
}

} // namespace tables
} // namespace osquery
