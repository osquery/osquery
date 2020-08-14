/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/property_tree/ptree.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sqlite_util.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/darwin/plist.h>

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

/**
 * @brief The Apple reference date offset.
 *
 * Some Apple epoch dates use 1/1/2001 UTC as the beginning of time.
 * Since *most* things in osquery are UNIX epoch, append the 1970's offset.
 */
const size_t kReferenceDateOffset = 978307200;

/// Basic GLOB pattern for discovering caches.
const std::string kQuicklookPattern =
    "/private/var/folders/%/%/%/com.apple.QuickLook.thumbnailcache/"
    "index.sqlite";

void genQuicklookRow(sqlite3_stmt* stmt, Row& r) {
  for (int i = 0; i < sqlite3_column_count(stmt); i++) {
    auto column_name = std::string(sqlite3_column_name(stmt, i));
    auto column_type = sqlite3_column_type(stmt, i);
    if (column_type == SQLITE_TEXT) {
      auto value = sqlite3_column_text(stmt, i);
      if (value != nullptr) {
        r[column_name] = std::string((const char*)value);
      }
    } else if (column_type == SQLITE_INTEGER) {
      // Handle INTEGER columns explicitly to handle the date-value offset.
      auto value = sqlite3_column_int64(stmt, i);
      if (column_name == "last_hit_date") {
        value += kReferenceDateOffset;
      }
      r[column_name] = INTEGER(value);
    } else if (column_type == SQLITE_BLOB) {
      // Handle BLOB values explicitly to avoid the default char* termination
      // for binary-plist data.
      auto getField = [](const pt::ptree& tree, const std::string& field) {
        if (field == "mtime" && tree.count(field) > 0) {
          // Apply a special case for embedded date-value fields.
          return INTEGER(tree.get<size_t>(field) + kReferenceDateOffset);
        }
        return (tree.count(field) > 0) ? tree.get<std::string>(field) : "";
      };

      if (column_name == "version") {
        pt::ptree tree;
        auto version = std::string((const char*)sqlite3_column_blob(stmt, i),
                                   sqlite3_column_bytes(stmt, i));
        if (parsePlistContent(version, tree)) {
          r["mtime"] = getField(tree, "date");
          r["size"] = getField(tree, "size");
          r["label"] = getField(tree, "gen");
        }
      }
    }
  }

  // Transform the folder/file_name into an aggregate path.
  r["path"] = std::move(r["folder"]) + "/" + std::move(r["file_name"]);
  r.erase("folder");
  r.erase("file_name");

  // Transform the encoded fs_id.
  auto details = osquery::split(r["fs_id"], "=.");
  if (details.size() == 4) {
    r["volume_id"] = details[2];
    r["inode"] = details[3];
  }
}

QueryData genQuicklookCache(QueryContext& context) {
  QueryData results;

  // There may be several quick look caches.
  // Apply a GLOB search since the folder is randomized.
  std::vector<std::string> databases;
  if (!resolveFilePattern(kQuicklookPattern, databases)) {
    return results;
  }

  for (const auto& index : databases) {
    sqlite3* db = nullptr;
    auto rc = sqlite3_open_v2(
        index.c_str(), &db,
        (SQLITE_OPEN_READONLY | SQLITE_OPEN_PRIVATECACHE | SQLITE_OPEN_NOMUTEX),
        nullptr);
    if (rc != SQLITE_OK || db == nullptr) {
      VLOG(1) << "Cannot open " << index << " read only: "
              << rc << " " << getStringForSQLiteReturnCode(rc);
      if (db != nullptr) {
        sqlite3_close(db);
      }
      continue;
    }

    // QueryData file_results;
    std::string query =
        "SELECT f.*, last_hit_date, hit_count, icon_mode FROM (SELECT rowid, * "
        "FROM files) f, (SELECT *, max(last_hit_date) AS last_hit_date FROM "
        "thumbnails GROUP BY file_id) t WHERE t.file_id = rowid;";
    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
      Row r;
      genQuicklookRow(stmt, r);

      // For each row added to the results from this database, add the path to
      // the database, then move into the table's result set.
      r["cache_path"] = index;
      results.push_back(r);
    }

    // Clean up.
    sqlite3_finalize(stmt);
    sqlite3_close(db);
  }

  return results;
}
}
}
