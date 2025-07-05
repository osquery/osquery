/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>
#include <vector>

namespace osquery {

/**
 * @brief Check if a string starts with any prefix in a vector.
 *
 * @param s the string to be validated.
 * @param prefixes vector of prefixes to be matched against.
 *
 * @return true if string contains any of the prefixes.
 */
bool hasAnyPrefix(const std::string& s,
                  const std::vector<std::string>& prefixes);

/**
 * @brief Check if a string ends with any suffix in a vector.
 *
 * @param s the string to be validated.
 * @param suffixes vector of suffixes to be matched against.
 *
 * @return true if string contains any of the suffixes.
 */
bool hasAnySuffix(const std::string& s,
                  const std::vector<std::string>& suffixes);

} // namespace osquery
