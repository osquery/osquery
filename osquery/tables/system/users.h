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
 * @param context The context given to a table implementation.
 * @return A complete set of rows for each user.
 */
QueryData genUsers(QueryContext& context);

} // namespace tables
} // namespace osquery
