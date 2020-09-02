/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/time.h>

#include <boost/algorithm/string/trim.hpp>

#include <cstring>
#include <ctime>

namespace osquery {

std::string toAsciiTime(const struct tm* tm_time) {
  if (tm_time == nullptr) {
    return "";
  }

  auto time_str = platformAsctime(tm_time);
  boost::algorithm::trim(time_str);
  return time_str + " UTC";
}

std::string toAsciiTimeUTC(const struct tm* tm_time) {
  uint64_t epoch = toUnixTime(tm_time);
  struct tm tptr;

  std::memset(&tptr, 0, sizeof(tptr));

  if (epoch == (size_t)-1) {
    return "";
  }

#ifdef OSQUERY_WINDOWS
  _gmtime64_s(&tptr, (time_t*)&epoch);
#else
  gmtime_r((time_t*)&epoch, &tptr);
#endif
  return toAsciiTime(&tptr);
}

std::string getAsciiTime() {
  auto result = std::time(nullptr);

  struct tm now;
#ifdef OSQUERY_WINDOWS
  _gmtime64_s(&now, &result);
#else
  gmtime_r(&result, &now);
#endif

  return toAsciiTime(&now);
}

uint64_t toUnixTime(const struct tm* tm_time) {
  struct tm result;
  std::memset(&result, 0, sizeof(result));

  std::memcpy(&result, tm_time, sizeof(result));
  return mktime(&result);
}

uint64_t getUnixTime() {
  std::time_t ut = std::time(nullptr);
  return ut < 0 ? 0 : ut;
}

} // namespace osquery
