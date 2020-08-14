/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/time.h>

#include <string.h>

namespace osquery {

std::string platformAsctime(const struct tm* timeptr) {
  if (timeptr == nullptr) {
    return "";
  }

  // Manual says at least 26 characters.
  char buffer[32] = {0};
  return ::asctime_r(timeptr, buffer);
}

} // namespace osquery
