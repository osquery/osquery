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

#include <string>
#include <time.h>
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

LONGLONG parseFatTime(const std::string& fat_data) {
  if (fat_data.length() != 8) {
    LOG(WARNING)
        << "Incorrect FAT timestamp format, expecting string length 8, got: "
        << fat_data;
    return 0ll;
  }
  std::string fat_date_data = fat_data.substr(0, 4);
  std::string fat_time_data = fat_data.substr(4, 4);

  auto fat_date = std::stoi(fat_date_data.substr(2, 2), nullptr, 16) << 8;
  fat_date |= std::stoi(fat_date_data.substr(0, 2), nullptr, 16);

  // Year is stored as number of years after 1980. Ex: 2020 is stored as 40
  int fat_year = ((fat_date & 0xfe00) >> 9) + 1980;
  int fat_month = (fat_date & 0x1e0) >> 5;
  int fat_day = fat_date & 0x1f;

  auto fat_time = std::stoi(fat_time_data.substr(2, 2), nullptr, 16) << 8;
  fat_time |= std::stoi(fat_time_data.substr(0, 2), nullptr, 16);
  int fat_sec = (fat_time & 0x1f) * 2;
  int fat_min = (fat_time & 0x7e0) >> 5;
  int fat_hour = (fat_time & 0xf800) >> 11;

  struct tm fat_timestamp = {0};
  fat_timestamp.tm_year = fat_year - 1900;
  fat_timestamp.tm_mon = fat_month - 1;
  fat_timestamp.tm_mday = fat_day;
  fat_timestamp.tm_hour = fat_hour;
  fat_timestamp.tm_min = fat_min;
  fat_timestamp.tm_sec = fat_sec;

  time_t epoch = _mkgmtime(&fat_timestamp);
  return epoch;
}

LONGLONG bigEndianFiletimeToUnixTime(const std::string& time_data) {
  if (time_data.length() != 16) {
    LOG(WARNING) << "bigEndianFiletimeToUnixTime expects 16 hex characters, "
                    "got length: "
                 << time_data.length();
    return 0LL;
  }

  auto filetime_long = tryTo<unsigned long long>(time_data, 16);
  if (filetime_long.isError()) {
    LOG(WARNING) << "Failed to parse hex FILETIME string: " << time_data;
    return 0LL;
  }

  FILETIME ft;
  ULARGE_INTEGER uli;
  uli.QuadPart = filetime_long.get();
  ft.dwHighDateTime = uli.HighPart;
  ft.dwLowDateTime = uli.LowPart;

  return filetimeToUnixtime(ft);
}

LONGLONG parseDateToUnixTime(const std::string& date_str) {
  if (date_str.empty()) {
    return 0LL;
  }

  int a = 0, b = 0, c = 0;
  int year = 0, month = 0, day = 0;

  // Try slash-separated format: M/D/YYYY (US locale, most common)
  if (sscanf(date_str.c_str(), "%d/%d/%d", &a, &b, &c) == 3) {
    month = a;
    day = b;
    year = c;
  }
  // Try dash-separated format
  else if (sscanf(date_str.c_str(), "%d-%d-%d", &a, &b, &c) == 3) {
    // If first number looks like a year (>31), assume ISO format YYYY-MM-DD
    if (a > 31) {
      year = a;
      month = b;
      day = c;
    } else {
      // Otherwise assume D-M-YYYY
      day = a;
      month = b;
      year = c;
    }
  } else {
    return 0LL;
  }

  // Validate parsed values
  if (year >= 1970 && year <= 2100 && month >= 1 && month <= 12 && day >= 1 &&
      day <= 31) {
    struct tm timestamp = {0};
    timestamp.tm_year = year - 1900;
    timestamp.tm_mon = month - 1;
    timestamp.tm_mday = day;
    return static_cast<LONGLONG>(_mkgmtime(&timestamp));
  }

  return 0LL;
}

} // namespace osquery
