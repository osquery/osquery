/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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
