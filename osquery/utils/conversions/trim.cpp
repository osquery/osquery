/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "trim.h"

#include <cctype>

namespace osquery {
std::string_view trim(std::string_view input) {
  std::size_t start = 0;
  for (;; ++start) {
    if (start == input.size()) {
      return {};
    }

    if (!std::isspace(input[start])) {
      break;
    }
  }

  std::size_t end = input.size() - 1;
  for (; end > start && std::isspace(input[end]); --end)
    ;

  return std::string_view(&input[start], (end - start) + 1);
}
} // namespace osquery
