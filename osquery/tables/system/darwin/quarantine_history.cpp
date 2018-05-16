/*
 *  Copyright (c) 2018-present, Facebook, Inc.
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
#include "osquery/tables/system/system_utils.h"

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

// Path (after /Users/foo) where the quarantine events DB will be found
const std::string kQuarantineEventsDbPath =
    "Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2";

const int cocoaToUnixEpochOffset = 978307200;

void genQuarantineEventRow(sqlite3_stmt* const stmt,
                           const std::string& uid,
                           Row& r) {
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
      // convert to UNIX epoch
      if (column_name == "timestamp") {
        auto timestamp = value + cocoaToUnixEpochOffset;
        r[column_name] = DOUBLE(timestamp);
      } else {
        r[column_name] = DOUBLE(value);
      }
    } else if (column_type == SQLITE_INTEGER) {
      auto value = sqlite3_column_int(stmt, i);
      r[column_name] = INTEGER(value);
    }
  }
  r["uid"] = INTEGER(uid);
}

void genQuarantineHistoryItems(const fs::path& qepath,
                               const std::string& uid,
                               QueryData& results) {
  sqlite3* db = nullptr;

  if (!pathExists(qepath).ok()) {
    return;
  }

  auto rc = sqlite3_open_v2(
      qepath.c_str(),
      &db,
      (SQLITE_OPEN_READONLY | SQLITE_OPEN_PRIVATECACHE | SQLITE_OPEN_NOMUTEX),
      nullptr);
  if (rc != SQLITE_OK || db == nullptr) {
    VLOG(1) << "Cannot open Quarantine Events DB: " << rc << " "
            << getStringForSQLiteReturnCode(rc);
    if (db != nullptr) {
      sqlite3_close(db);
    }
  }

  const std::string query =
      "SELECT LSQuarantineEventIdentifier as id, LSQuarantineAgentName as "
      "agent_name, LSQuarantineAgentBundleIdentifier as "
      "agent_bundle_identifier, LSQuarantineTypeNumber as type,  "
      "LSQuarantineDataURLString as data_url,LSQuarantineOriginURLString as "
      "origin_url, LSQuarantineSenderName as sender_name, "
      "LSQuarantineSenderAddress as sender_address, LSQuarantineTimeStamp as "
      "timestamp from LSQuarantineEvent";
  sqlite3_stmt* stmt = nullptr;
  rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
  while ((sqlite3_step(stmt)) == SQLITE_ROW) {
    Row r;
    genQuarantineEventRow(stmt, uid, r);
    results.push_back(r);
  }

  // Clean up.
  sqlite3_finalize(stmt);
  sqlite3_close(db);
}

QueryData genQuarantineHistory(QueryContext& context) {
  QueryData results;

  // Iterate over each user
  auto users = usersFromContext(context);
  for (const auto& user : users) {
    auto qepath = fs::path(user.at("directory")) / kQuarantineEventsDbPath;
    auto uid = user.find("uid");
    genQuarantineHistoryItems(qepath.string(), uid->second, results);
  }

  return results;
}
} // namespace tables
} // namespace osquery
