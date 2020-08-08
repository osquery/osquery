/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <string>

namespace osquery {

/**
 * @brief Decode a rot13 encoded string.
 *
 * @param rot_string The encode rot13 string.
 * @return Decoded string.
 */
std::string rotDecode(std::string& rot_string);

} // namespace osquery