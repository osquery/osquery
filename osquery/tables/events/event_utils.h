/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <set>
#include <string>

#include <osquery/core/tables.h>

namespace osquery {

/// List of columns decorated for file events.
extern const std::set<std::string> kCommonFileColumns;

/**
 * @brief A helper function for each platform's implementation of file_events.
 *
 * Given an action and path, this Row decorator assures a common implementation
 * of hashing and common columns from the `file` table.
 *
 * @param path The target path from the file event.
 * @param hash Should the target path be read and hashed.
 * @param r The output parameter row structure.
 */
void decorateFileEvent(const std::string& path, bool hash, Row& r);
}
