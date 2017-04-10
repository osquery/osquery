/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string.h>
#include <time.h>

#include "osquery/core/utils.h"

namespace osquery {

std::string platformAsctime(const struct tm* timeptr) {
  if (timeptr == nullptr) {
    return "";
  }

  return ::asctime(timeptr);
}

std::string platformStrerr(int errnum) {
  return ::strerror(errnum);
}

Status platformStrncpy(char* dst, size_t nelms, const char* src, size_t count) {
  if (dst == nullptr || src == nullptr || nelms == 0) {
    return Status(1, "Failed to strncpy: invalid arguments");
  }

  if (count > nelms) {
    return Status(1, "Failed to strncpy: dst too small");
  }

  ::strncpy(dst, src, count);
  return Status(0, "OK");
}
}
