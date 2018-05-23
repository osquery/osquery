/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <string.h>
#include <time.h>

#include "osquery/core/utils.h"

namespace osquery {

std::string platformAsctime(const struct tm* timeptr) {
  if (timeptr == nullptr) {
    return "";
  }

  // Manual says at least 26 characters.
  char buffer[32] = {0};
  return ::asctime_r(timeptr, buffer);
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

char* canonicalize_file_name(char* name) {
  // This implementaion mimic behaviour of realpath
  // function with NULL as buffer, except the fact
  // that default fallback buffer is 4096 instead of 1024
  // since PATH_MAX default value is usually 4096+
  // In modern versions of libc pathing PATH_MAX buffer
  // is safe and will be handled corrrectly.
  // There is no strong evidence that using PATH_MAX can lead to
  // buffer overflow on supported OS versions

  long int path_max = 0;
#ifdef PATH_MAX
  path_max = PATH_MAX;
#else
  path_max = pathconf(name, _PC_PATH_MAX);
  if (path_max <= 0) {
    path_max = 1024 * 4;
  }
#endif
  char* buffer = reinterpret_cast<char*>(malloc(path_max));
  char* resolved = realpath(name, buffer);
  if (resolved == nullptr) {
    free(buffer);
    return nullptr;
  }
  return resolved;
}

} // namespace osquery
