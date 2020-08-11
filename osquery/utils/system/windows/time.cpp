/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/status/status.h>
#include <osquery/utils/system/time.h>

#include <string.h>
#include <vector>

#include <Windows.h>
#include <boost/algorithm/string.hpp>

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
} // namespace osquery
