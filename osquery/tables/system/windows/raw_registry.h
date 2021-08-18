/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/core/core.h>
#include <osquery/core/tables.h>

#include <vector>

namespace osquery {
namespace tables {

/**
 * @brief Windows helper function for getting physical drives
 *
 * @returns Array of physical drives
 */
std::vector<std::string> getDrives();

/**
 * @brief Windows helper function for formatting paths for Sleuthkit
 *
 */
void cleanRegPath(std::string& reg_path);
} // namespace tables
} // namespace osquery