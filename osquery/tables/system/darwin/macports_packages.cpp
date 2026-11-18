/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <set>
#include <string>

#include <boost/filesystem/path.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sqlite_util.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

/// genPortRow and portsFromPrefix are intentionally non-static so the unit
/// test can drive them against a fixture registry.

/// Default MacPorts install prefixes.
///
/// /opt/local is the documented default. A user may select another prefix at
/// install time, in which case the `prefix` column can be constrained to it.
const std::set<std::string> kMacPortsPrefixes = {
    "/opt/local",
};

/// MacPorts records installed ports in a SQLite registry beneath the prefix.
const std::string kMacPortsRegistryPath = "var/macports/registry/registry.db";

/// MacPorts uses two states: 'installed' means activated, with the port's files
/// linked into the prefix; 'imaged' means unpacked into the image directory but
/// deactivated, so nothing is linked. Only 'installed' ports are usable, which
/// is also what `port installed` reports.
const std::string kMacPortsQuery =
    "SELECT name, version, revision, variants, archs, requested, date "
    "FROM ports WHERE state = 'installed';";

void genPortRow(sqlite3_stmt* stmt, Row& r) {
  for (int i = 0; i < sqlite3_column_count(stmt); i++) {
    auto column_name = std::string(sqlite3_column_name(stmt, i));
    auto column_type = sqlite3_column_type(stmt, i);

    // The registry stores `archs`; the table exposes it as `arch`, matching the
    // singular column name used elsewhere in osquery.
    if (column_name == "archs") {
      column_name = "arch";
    }

    if (column_type == SQLITE_TEXT) {
      auto value = sqlite3_column_text(stmt, i);
      if (value != nullptr) {
        r[column_name] = std::string((const char*)value);
      }
    } else if (column_type == SQLITE_INTEGER) {
      r[column_name] = INTEGER(sqlite3_column_int64(stmt, i));
    }
  }
}

void portsFromPrefix(QueryData& results,
                     const std::string& prefix,
                     bool userRequested) {
  auto registry = (fs::path(prefix) / kMacPortsRegistryPath).string();

  if (!pathExists(registry).ok()) {
    if (userRequested) {
      LOG(WARNING) << "Error reading MacPorts registry " << registry;
    }
    return;
  }

  sqlite3* db = nullptr;
  auto rc = sqlite3_open_v2(
      registry.c_str(),
      &db,
      (SQLITE_OPEN_READONLY | SQLITE_OPEN_PRIVATECACHE | SQLITE_OPEN_NOMUTEX),
      nullptr);
  if (rc != SQLITE_OK || db == nullptr) {
    VLOG(1) << "Cannot open " << registry << " read only: " << rc << " "
            << getStringForSQLiteReturnCode(rc);
    if (db != nullptr) {
      sqlite3_close(db);
    }
    return;
  }

  sqlite3_stmt* stmt = nullptr;
  rc = sqlite3_prepare_v2(db, kMacPortsQuery.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    VLOG(1) << "Cannot query " << registry << ": " << rc << " "
            << getStringForSQLiteReturnCode(rc);
    sqlite3_close(db);
    return;
  }

  while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
    Row r;
    genPortRow(stmt, r);
    r["prefix"] = prefix;
    results.push_back(r);
  }

  sqlite3_finalize(stmt);
  sqlite3_close(db);
}

QueryData genMacPortsPackages(QueryContext& context) {
  QueryData results;

  if (context.constraints.count("prefix") > 0 &&
      context.constraints.at("prefix").exists(EQUALS)) {
    std::set<std::string> prefixes =
        context.constraints["prefix"].getAll(EQUALS);
    for (const auto& prefix : prefixes) {
      portsFromPrefix(results, prefix, true);
    }
  } else {
    // No prefixes requested, fall back to the system ones.
    for (const auto& prefix : kMacPortsPrefixes) {
      portsFromPrefix(results, prefix, false);
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
