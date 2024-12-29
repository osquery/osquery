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
 * @brief Extract path and arguments from a command line string in input
 *
 * If no user is provided the current user is returned.
 *
 * @param cmdline The command line string in input
 * @param r  A row where to store `path` and `args`
 * @return true if extraction was succeeded, false otherwise
 */
bool parseStartupPath(const std::string& cmdline, Row& r);

} // namespace tables
} // namespace osquery
