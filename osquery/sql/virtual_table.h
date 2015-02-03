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

#include <osquery/tables.h>

#include "osquery/sql/sqlite_util.h"

namespace osquery {
namespace tables {

/**
 * @brief osquery cursor object.
 *
 * Only used in the SQLite virtual table module methods.
 */
struct BaseCursor {
  /// SQLite virtual table cursor.
  sqlite3_vtab_cursor base;
  /// Current cursor position.
  int row;
};

struct VirtualTableContent {
  TableName name;
  TableColumns columns;
  TableData data;
  ConstraintSet constraints;
  size_t n;
};

/**
 * @brief osquery virtual table object
 *
 * Only used in the SQLite virtual table module methods.
 * This adds each table plugin class to the state tracking in SQLite.
 */
struct VirtualTable {
  sqlite3_vtab base;
  VirtualTableContent *content;
};

/// Attach a table plugin name to an in-memory SQLite datable.
int attachTable(sqlite3 *db, const std::string &name);

/// Attach all table plugins to an in-memory SQLite datable.
void attachVirtualTables(sqlite3 *db);
}
}
