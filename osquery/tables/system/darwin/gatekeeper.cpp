/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sqlite_util.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

const std::string kGkeStatusPath = "/var/db/SystemPolicy-prefs.plist";

const std::string kGkeBundlePath = "/var/db/gke.bundle/Contents/version.plist";

const std::string kGkeOpaquePath =
    "/var/db/gkopaque.bundle/Contents/version.plist";

const std::string kPolicyDb = "/var/db/SystemPolicy";

bool isGateKeeperDevIdEnabled() {
  sqlite3* db = nullptr;
  auto rc = sqlite3_open_v2(
      kPolicyDb.c_str(),
      &db,
      (SQLITE_OPEN_READONLY | SQLITE_OPEN_PRIVATECACHE | SQLITE_OPEN_NOMUTEX),
      nullptr);
  if (rc != SQLITE_OK || db == nullptr) {
    VLOG(1) << "Cannot open Gatekeeper DB: " << rc << " "
            << getStringForSQLiteReturnCode(rc);
    if (db != nullptr) {
      sqlite3_close(db);
    }
    return false;
  }

  std::string query =
      "SELECT disabled FROM authority WHERE label = 'Developer ID'";
  sqlite3_stmt* stmt = nullptr;
  rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    if (stmt != nullptr) {
      sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return false;
  }

  while ((sqlite3_step(stmt)) == SQLITE_ROW) {
    int value = sqlite3_column_int(stmt, 0);
    if (value == 1) {
      // Clean up.
      sqlite3_finalize(stmt);
      sqlite3_close(db);
      // return false if any rows say "disabled"
      return false;
    }
  }
  sqlite3_finalize(stmt);
  sqlite3_close(db);
  return true;
}

QueryData genGateKeeper(QueryContext& context) {
  Row r;

  auto gke_status = SQL::selectAllFrom("plist", "path", EQUALS, kGkeStatusPath);

  if (gke_status.empty()) {
    // The absence of the file indicates that Gatekeeper is fully enabled
    r["assessments_enabled"] = INTEGER(1);
    r["dev_id_enabled"] = INTEGER(1);
  }

  for (const auto& row : gke_status) {
    if (row.find("key") == row.end() || row.find("value") == row.end()) {
      continue;
    }
    if (row.at("key") == "enabled" && row.at("value") == "yes") {
      r["assessments_enabled"] = INTEGER(1);
      r["dev_id_enabled"] =
          isGateKeeperDevIdEnabled() ? INTEGER(1) : INTEGER(0);
    } else {
      r["assessments_enabled"] = INTEGER(0);
      r["dev_id_enabled"] = INTEGER(0);
    }
  }

  auto gke_bundle = SQL::selectAllFrom("plist", "path", EQUALS, kGkeBundlePath);

  if (gke_bundle.empty()) {
    r["version"] = std::string();
  }

  for (const auto& row : gke_bundle) {
    if (row.find("key") == row.end() || row.find("value") == row.end()) {
      continue;
    }
    if (row.at("key") == "CFBundleShortVersionString") {
      r["version"] = row.at("value");
    }
  }

  auto gke_opaque = SQL::selectAllFrom("plist", "path", EQUALS, kGkeOpaquePath);

  if (gke_opaque.empty()) {
    r["opaque_version"] = std::string();
  }

  for (const auto& row : gke_opaque) {
    if (row.find("key") == row.end() || row.find("value") == row.end()) {
      continue;
    }
    if (row.at("key") == "CFBundleShortVersionString") {
      r["opaque_version"] = row.at("value");
    }
  }
  return {r};
}

void genGateKeeperApprovedAppRow(sqlite3_stmt* const stmt, Row& r) {
  for (int i = 0; i < sqlite3_column_count(stmt); i++) {
    auto column_name = std::string(sqlite3_column_name(stmt, i));
    auto column_type = sqlite3_column_type(stmt, i);
    if (column_type == SQLITE_TEXT) {
      auto value = sqlite3_column_text(stmt, i);
      if (value != nullptr) {
        r[column_name] = std::string(reinterpret_cast<const char*>(value));
      }
    } else if (column_type == SQLITE_FLOAT) {
      auto value = sqlite3_column_double(stmt, i);
      r[column_name] = DOUBLE(value);
    }
  }
}

QueryData genGateKeeperApprovedApps(QueryContext& context) {
  QueryData results;

  sqlite3* db = nullptr;

  auto rc = sqlite3_open_v2(
      kPolicyDb.c_str(),
      &db,
      (SQLITE_OPEN_READONLY | SQLITE_OPEN_PRIVATECACHE | SQLITE_OPEN_NOMUTEX),
      nullptr);
  if (rc != SQLITE_OK || db == nullptr) {
    VLOG(1) << "Cannot open Gatekeeper DB: " << rc << " "
            << getStringForSQLiteReturnCode(rc);
    if (db != nullptr) {
      sqlite3_close(db);
    }
    return results;
  }

  const std::string query =
      "SELECT remarks as path, requirement, ctime, mtime from authority WHERE "
      "disabled = 0 AND JULIANDAY('now') < expires AND (flags & 1) = 0 AND "
      "label is NULL";
  sqlite3_stmt* stmt = nullptr;
  rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
  while ((sqlite3_step(stmt)) == SQLITE_ROW) {
    Row r;
    genGateKeeperApprovedAppRow(stmt, r);
    results.push_back(r);
  }

  // Clean up.
  sqlite3_finalize(stmt);
  sqlite3_close(db);

  return results;
}
} // namespace tables
} // namespace osquery
