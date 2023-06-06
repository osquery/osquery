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
#include <string_view>

namespace osquery {

namespace base64 {

/**
 * @brief Decode a base64 encoded string.
 *
 * @param encoded The encode base64 string.
 * @return Decoded string.
 */
std::string decode(std::string_view encoded);

/**
 * @brief Decode a base64 encoded string in the form of rvalue reference.
 *
 * This function can change the encoded string content.
 *
 * @param encoded The encode base64 string.
 * @return Decoded string.
 */
std::string decode(std::string&& encoded);

/**
 * @brief Encode a  string.
 *
 * @param A string to encode.
 * @return Encoded string.
 */
std::string encode(std::string_view unencoded);

} // namespace base64

} // namespace osquery
