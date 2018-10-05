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
#include <vector>

#include <boost/algorithm/string.hpp>

#include "osquery/core/utils.h"

#define MAX_BUFFER_SIZE 256

namespace osquery {

std::string platformAsctime(const struct tm* timeptr) {
  std::vector<char> buffer;
  buffer.assign(MAX_BUFFER_SIZE, '\0');

  auto status = ::asctime_s(buffer.data(), buffer.size(), timeptr);
  if (status != 0) {
    return "";
  }

  std::string time_str(buffer.data());
  boost::replace_all(time_str, "\n", "");
  return time_str;
}

std::string platformStrerr(int errnum) {
  std::vector<char> buffer;
  buffer.assign(MAX_BUFFER_SIZE, '\0');

  auto status = ::strerror_s(buffer.data(), buffer.size(), errnum);
  if (status != 0) {
    return "";
  }

  return std::string(buffer.data());
}

}
