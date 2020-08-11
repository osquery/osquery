/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <memory>

#include <boost/noncopyable.hpp>

#include <osquery/core/tables.h>
#include <osquery/sql/sqlite_util.h>

namespace osquery {

/**
 * @brief A protection around concurrent table attach requests.
 *
 * Table attaching is not concurrent. Attaching is the only unprotected SQLite
 * operation from osquery's usage perspective. The extensions API allows for
 * concurrent access of non-thread-safe database resources for attaching table
 * schema and filter routing instructions.
 */
extern RecursiveMutex kAttachMutex;

/**
 * @brief osquery cursor object.
 *
 * Only used in the SQLite virtual table module methods.
 */
struct BaseCursor : private boost::noncopyable {
 public:
  /// SQLite virtual table cursor.
  sqlite3_vtab_cursor base;

  /// Track cursors for optional planner output.
  size_t id{0};

  /// Table data generated from last access.
  TableRows rows;

  /// Callable generator.
  std::unique_ptr<RowGenerator::pull_type> generator{nullptr};

  /// Results of current call.
  TableRowHolder current;

  /// Does the backing local table use a generator type.
  bool uses_generator{false};

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
  std::shared_ptr<VirtualTableContent> content;

  /// Added structure: The thread-local DB instance associated with the query.
  SQLiteDBInstance* instance{nullptr};
};

/// Attach a table plugin name to an in-memory SQLite database.
Status attachTableInternal(const std::string& name,
                           const std::string& statement,
                           const SQLiteDBInstanceRef& instance,
                           bool is_extension);

/// Detach (drop) a table.
Status detachTableInternal(const std::string& name,
                           const SQLiteDBInstanceRef& instance);

Status attachFunctionInternal(
    const std::string& name,
    std::function<
        void(sqlite3_context* context, int argc, sqlite3_value** argv)> func);

/// Attach all table plugins to an in-memory SQLite database.
void attachVirtualTables(const SQLiteDBInstanceRef& instance);

#if !defined(OSQUERY_EXTERNAL)
/**
 * A generated foreign amalgamation file includes schema for all tables.
 *
 * When the build system generates TablePlugin%s from the .table spec files, it
 * reads the foreign-platform tables and generates an associated schema plugin.
 * These plugins are amalgamated into 'foreign_amalgamation' and do not call
 * their filter generation functions.
 */
void registerForeignTables();
#endif
} // namespace osquery
