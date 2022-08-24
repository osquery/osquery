/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string_view>

namespace osquery {
/**
 * @brief Adjusts the string_view so that all leading
 * and trailing spaces are out
 *
 * @param input
 * @return std::string_view
 */
std::string_view trim(std::string_view input);
} // namespace osquery
