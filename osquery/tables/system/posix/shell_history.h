/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/sql/dynamic_table_row.h>

#include <string>

namespace osquery {
namespace tables {

/// This takes a predicate function to aide testing.
void genShellHistoryFromBashSessions(
    const std::string& uid,
    const std::string& directory,
    std::function<void(DynamicTableRowHolder& row)> predicate);

/// This takes a predicate function to aide testing.
void genShellHistoryForUser(
    const std::string& uid,
    const std::string& gid,
    const std::string& directory,
    std::function<void(DynamicTableRowHolder& row)> predicate);

} // namespace tables
} // namespace osquery
