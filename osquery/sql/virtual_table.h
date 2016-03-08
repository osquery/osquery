/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <boost/noncopyable.hpp>

#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/sql/sqlite_util.h"

namespace osquery {

/**
 * @brief osquery cursor object.
 *
 * Only used in the SQLite virtual table module methods.
 */
struct BaseCursor : private boost::noncopyable {
  /// SQLite virtual table cursor.
  sqlite3_vtab_cursor base;
  /// Track cursors for optional planner output.
  size_t id{0};
  /// Table data generated from last access.
  QueryData data;
  /// Current cursor position.
  size_t row{0};
  /// Total number of rows.
  size_t n{0};
};

/**
 * @brief osquery virtual table object
 *
 * Only used in the SQLite virtual table module methods.
 * This adds each table plugin class to the state tracking in SQLite.
 */
struct VirtualTable : private boost::noncopyable {
  /// The SQLite-provided virtual table structure.
  sqlite3_vtab base;

  /// Added structure: A content structure with metadata about the table.
  VirtualTableContent *content{nullptr};

  /// Added structure: The thread-local DB instance associated with the query.
  SQLiteDBInstance *instance{nullptr};
};

/// Attach a table plugin name to an in-memory SQLite database.
Status attachTableInternal(const std::string &name,
                           const std::string &statement,
                           const SQLiteDBInstanceRef &instance);

/// Detach (drop) a table.
Status detachTableInternal(const std::string &name, sqlite3 *db);

/// Attach all table plugins to an in-memory SQLite database.
void attachVirtualTables(const SQLiteDBInstanceRef &instance);
}
