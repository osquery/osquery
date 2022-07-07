/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <map>
#include <set>
#include <string>
#include <vector>

namespace osquery {

/*
 * @brief Column options allow for more-complicated modeling of concepts.
 *
 * To accommodate the oddities of operating system concepts we make use of
 * simple SQLite abstractions like indexes/keys and foreign keys, we also
 * allow for optimizing based on query constraints (WHERE).
 *
 * There are several 'complications' where the default table filter (SELECT)
 * behavior attempts to mimic reality. Browser plugins or shell history are
 * good examples, a SELECT without using a WHERE returns the plugins or
 * history as it applies to the user running the query. If osquery is meant
 * to be a daemon with absolute visibility this introduces an abnormality,
 * as the expected result will only include the superuser's view, even if
 * the superuser can view everything if they intended.
 *
 * The solution is to explicitly ask for everything, by joining against the
 * users table. This options structure will allow the table implementations
 * to communicate these subtleties to the user.
 */
enum class ColumnOptions {
  /// Default/no options.
  DEFAULT = 0,

  /// Treat this column as a primary key.
  INDEX = 1,

  /// This column MUST be included in the query predicate.
  REQUIRED = 2,

  /*
   * @brief This column is used to generate additional information.
   *
   * If this column is included in the query predicate, the table will generate
   * additional information. Consider the browser_plugins or shell history
   * tables: by default they list the plugins or history relative to the user
   * running the query. However, if the calling query specifies a UID explicitly
   * in the predicate, the meaning of the table changes and results for that
   * user are returned instead.
   */
  ADDITIONAL = 4,

  /*
   * @brief This column can be used to optimize the query.
   *
   * If this column is included in the query predicate, the table will generate
   * optimized information. Consider the system_controls table, a default filter
   * without a query predicate lists all of the keys. When a specific domain is
   * included in the predicate then the table will only issue syscalls/lookups
   * for that domain, greatly optimizing the time and utilization.
   *
   * This optimization does not mean the column is an index.
   */
  OPTIMIZED = 8,

  /// This column should be hidden from '*'' selects.
  HIDDEN = 16,

  // This sets the collating sequence to NOCASE
  COLLATENOCASE = 32,
};

/// Treat column options as a set of flags.
inline ColumnOptions operator|(ColumnOptions a, ColumnOptions b) {
  return static_cast<ColumnOptions>(static_cast<int>(a) | static_cast<int>(b));
}

/// Treat column options as a set of flags.
inline size_t operator&(ColumnOptions a, ColumnOptions b) {
  return static_cast<size_t>(a) & static_cast<size_t>(b);
}

enum ColumnType {
  UNKNOWN_TYPE = 0,
  TEXT_TYPE,
  INTEGER_TYPE,
  BIGINT_TYPE,
  UNSIGNED_BIGINT_TYPE,
  DOUBLE_TYPE,
  BLOB_TYPE,
};

/// Map of type constant to the SQLite string-name representation.
extern const std::map<ColumnType, std::string> kColumnTypeNames;

/// Helper alias for TablePlugin names.
using TableName = std::string;

/// Alias for an ordered list of column name and corresponding SQL type.
using TableColumns =
    std::vector<std::tuple<std::string, ColumnType, ColumnOptions>>;

/// Alias for map of column alias sets.
using ColumnAliasSet = std::map<std::string, std::set<std::string>>;

} // namespace osquery
