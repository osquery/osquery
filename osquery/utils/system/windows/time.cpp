/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/utils/status/status.h>
#include <osquery/utils/system/time.h>

#include <string.h>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <Windows.h>

#define MAX_BUFFER_SIZE 256

namespace osquery {
const auto kWindowsLanguageId = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);

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
