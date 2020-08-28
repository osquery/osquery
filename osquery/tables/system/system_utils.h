/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/core/tables.h>

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
