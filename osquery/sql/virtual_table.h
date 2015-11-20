/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <deque>

#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/sql/sqlite_util.h"

namespace osquery {

/**
 * @brief osquery virtual table connection.
 *
 * This object is the SQLite database's virtual table context.
 * When the virtual table is created/connected the name and columns are
 * retrieved via the TablePlugin call API. The details are kept in this context
 * so column parsing and row walking does not require additional Registry calls.
 *
 * When tables are accessed as the result of an SQL statement a QueryContext is
 * created to represent metadata that can be used by the virtual table
 * implementation code. Thus the code that generates rows can choose to emit
 * additional data, restrict based on constraints, or potentially yield from
 * a cache or choose not to generate certain columns.
 */
struct VirtualTableContent {
  /// Friendly name for the table.
  TableName name;
  /// Table column structure, retrieved once via the TablePlugin call API.
  TableColumns columns;
  /// Transient set of virtual table access constraints.
  std::deque<ConstraintSet> constraints;
  /// Index into the list of constraints.
  sqlite3_vtab_cursor *constraints_cursor{nullptr};
  size_t constraints_index{0};
  /// Last term successfully parsed by xBestIndex.
  int current_term{-1};
};

/**
 * @brief osquery cursor object.
 *
 * Only used in the SQLite virtual table module methods.
 */
struct BaseCursor {
  /// SQLite virtual table cursor.
  sqlite3_vtab_cursor base;
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
struct VirtualTable {
  sqlite3_vtab base;
  VirtualTableContent *content{nullptr};
};

/// Attach a table plugin name to an in-memory SQLite database.
Status attachTableInternal(const std::string &name,
                           const std::string &statement,
                           sqlite3 *db);

/// Detach (drop) a table.
Status detachTableInternal(const std::string &name, sqlite3 *db);

/// Attach all table plugins to an in-memory SQLite database.
void attachVirtualTables(sqlite3 *db);
}
