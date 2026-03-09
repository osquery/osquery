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
namespace tables {

/**
 * @brief Sanitize a string for use as an HTTP header value.
 *
 * Removes carriage return (\r) and line feed (\n) characters to prevent
 * HTTP header injection attacks (CRLF injection).
 *
 * @param value The string to sanitize
 * @return The sanitized string with CR/LF characters removed
 */
std::string sanitizeHttpHeaderValue(const std::string& value);

} // namespace tables
} // namespace osquery
