/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <string>

namespace osquery {

/**
 * @brief Check if a string is ASCII printable
 *
 * @param A string to check.
 * @return If the string is printable.
 */
bool isPrintable(const std::string& check);

/**
 * @brief In-line helper function for use with utf8StringSize
 */
template <typename _Iterator1, typename _Iterator2>
size_t incUtf8StringIterator(_Iterator1& it, const _Iterator2& last) {
  if (it == last) {
    return 0;
  }

  size_t res = 1;
  for (++it; last != it; ++it, ++res) {
    unsigned char c = *it;
    if (!(c & 0x80) || ((c & 0xC0) == 0xC0)) {
      break;
    }
  }

  return res;
}

/**
 * @brief Get the length of a UTF-8 string
 *
 * @param str The UTF-8 string
 *
 * @return the length of the string
 */
size_t utf8StringSize(const std::string& str);

/// Safely convert unicode escaped ASCII.
std::string unescapeUnicode(const std::string& escaped);

} // namespace osquery
