/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/rot13.h>

#include <string>

namespace osquery {

std::string rotDecode(const std::string& rot_string) {
  std::string decoded_string;

  for (std::size_t i = 0; i < rot_string.size(); i++) {
    if (isalpha(rot_string[i])) {
      if (rot_string[i] >= 'a' && rot_string[i] <= 'm') {
        decoded_string.append(1, rot_string[i] + 13);
      } else if (rot_string[i] >= 'm' && rot_string[i] <= 'z') {
        decoded_string.append(1, rot_string[i] - 13);
      } else if (rot_string[i] >= 'A' && rot_string[i] <= 'M') {
        decoded_string.append(1, rot_string[i] + 13);
      } else if (rot_string[i] >= 'M' && rot_string[i] <= 'Z') {
        decoded_string.append(1, rot_string[i] - 13);
      }
    } else {
      decoded_string.append(1, rot_string[i]);
    }
  }
  return decoded_string;
}
} // namespace osquery