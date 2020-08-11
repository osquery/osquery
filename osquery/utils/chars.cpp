/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <cstddef>

#include <osquery/logger/logger.h>

#include <osquery/utils/chars.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {

bool isPrintable(const std::string& check) {
  for (const unsigned char ch : check) {
    if (ch >= 0x7F || ch <= 0x1F) {
      return false;
    }
  }
  return true;
}

size_t utf8StringSize(const std::string& str) {
  size_t res = 0;
  std::string::const_iterator it = str.begin();
  for (; it != str.end(); incUtf8StringIterator(it, str.end())) {
    res++;
  }

  return res;
}

std::string unescapeUnicode(const std::string& escaped) {
  if (escaped.size() < 6) {
    return escaped;
  }

  std::string unescaped;
  unescaped.reserve(escaped.size());
  for (size_t i = 0; i < escaped.size(); ++i) {
    if (i < escaped.size() - 5 && '\\' == escaped[i] && 'u' == escaped[i + 1]) {
      // Assume 2-byte wide unicode.
      auto const exp = tryTo<long>(escaped.substr(i + 2, 4), 16);
      if (exp.isError()) {
        LOG(WARNING) << "Unescaping a string with length: " << escaped.size()
                     << " failed at: " << i;
        return "";
      }
      long const value = exp.get();
      if (value < 255) {
        unescaped += static_cast<char>(value);
        i += 5;
        continue;
      }
    } else if (i < escaped.size() - 1 && '\\' == escaped[i] &&
               '\\' == escaped[i + 1]) {
      // In the case of \\users 'sers' is not a unicode character
      // If we see \\ we should skip them and we do this by adding
      // an extra jump forward.
      unescaped += escaped[i];
      ++i;
    }
    unescaped += escaped[i];
  }
  return unescaped;
}

} // namespace osquery
