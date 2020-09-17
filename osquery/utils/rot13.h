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

namespace osquery {

/**
 * @brief Decode a rot13 encoded string.
 *
 * @param rot_string The encoded rot13 string.
 * @return Decoded string.
 */
std::string rotDecode(const std::string& rot_string);

} // namespace osquery