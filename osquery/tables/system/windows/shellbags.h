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

#include <string>
#include <vector>

namespace osquery {
namespace tables {

/**
 * @brief Parse a single REG_BINARY shellbag value (hex-encoded) into rows.
 *
 * @param shell_data Hex-encoded registry value (uppercase, no separators).
 * @param build_shellbag Path components accumulated from parent BagMRU entries.
 *                       Modified in place: the current entry's component is
 *                       appended.
 * @param results Output query rows. One row appended per call.
 * @param sid User SID this shellbag belongs to.
 * @param source "ntuser.dat" or "usrclass.dat".
 */
void parseShellData(const std::string& shell_data,
                    std::vector<std::string>& build_shellbag,
                    QueryData& results,
                    const std::string& sid,
                    const std::string& source);

} // namespace tables
} // namespace osquery
