/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/windows_time.h>

namespace osquery {

LONGLONG filetimeToUnixtime(const FILETIME& ft) {
  LARGE_INTEGER date, adjust;
  date.HighPart = ft.dwHighDateTime;
  date.LowPart = ft.dwLowDateTime;
  adjust.QuadPart = 11644473600000 * 10000;
  date.QuadPart -= adjust.QuadPart;
  return date.QuadPart / 10000000;
}

LONGLONG longIntToUnixtime(LARGE_INTEGER& li) {
  ULARGE_INTEGER ull;
  ull.LowPart = li.LowPart;
  ull.HighPart = li.HighPart;
  return ull.QuadPart / 10000000ULL - 11644473600ULL;
}

// Convert little endian Windows FILETIME to unix timestamp
LONGLONG littleEndianToUnixTime(const std::string& time_data) {
  std::string time_string = time_data;
  // swap endianess
  std::reverse(time_string.begin(), time_string.end());

  for (std::size_t i = 0; i < time_string.length(); i += 2) {
    std::swap(time_string[i], time_string[i + 1]);
  }

  // Convert string to long long
  unsigned long long filetime_long =
      tryTo<unsigned long long>(time_string, 16).takeOr(0ull);
  if (filetime_long == 0ull) {
    LOG(WARNING) << "Failed to convert string to long long: " << time_string;
    return 0LL;
  }

  FILETIME file_time;
  ULARGE_INTEGER large_time;
  large_time.QuadPart = filetime_long;
  file_time.dwHighDateTime = large_time.HighPart;
  file_time.dwLowDateTime = large_time.LowPart;
  auto last_time = filetimeToUnixtime(file_time);
  return last_time;
}

} // namespace osquery
