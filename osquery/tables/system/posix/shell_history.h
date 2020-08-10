/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/sql/dynamic_table_row.h>
#include <osquery/tables.h>

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
