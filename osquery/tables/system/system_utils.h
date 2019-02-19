/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/tables.h>

namespace osquery {
namespace tables {

/**
 * @brief Get a list of users given a context.
 *
 * If no user is provided the current user is returned.
 *
 * @param context The context given to a table implementation.
 * @param optional all Return all users regardless of context.
 * @return A complete set of rows for each user.
 */
QueryData usersFromContext(const QueryContext& context, bool all = false);

/**
 * Get a list of pids given a context.
 *
 * If no pid is provided all pids are returned.
 *
 * @param context The context given to a table implementation.
 * @param optional Return all pids regardless of context.
 * @return A complete set of rows for each process.
 */
QueryData pidsFromContext(const QueryContext& context, bool all = true);
}
}
