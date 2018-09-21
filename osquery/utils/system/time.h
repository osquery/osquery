/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <ctime>
#include <string>

namespace osquery {

/// Returns the ASCII version of the timeptr as a C++ string
std::string platformAsctime(const struct tm* timeptr);

/**
 * @brief Converts struct tm to a size_t
 *
 * @param tm_time the time/date to convert to UNIX epoch time
 *
 * @return an int representing the UNIX epoch time of the struct tm
 */
size_t toUnixTime(const struct tm* tm_time);

/**
 * @brief Getter for the current UNIX time.
 *
 * @return an int representing the amount of seconds since the UNIX epoch
 */
size_t getUnixTime();

/**
 * @brief Converts a struct tm into a human-readable format. This expected the
 * struct tm to be already in UTC time/
 *
 * @param tm_time the time/date to convert to ASCII
 *
 * @return the data/time of tm_time in the format: "Wed Sep 21 10:27:52 2011"
 */
std::string toAsciiTime(const struct tm* tm_time);

/**
 * @brief Converts a struct tm to ASCII time UTC by converting the tm_time to
 * epoch and then running gmtime() on the new epoch
 *
 * @param tm_time the local time/date to covert to UTC ASCII time
 *
 * @return the data/time of tm_time in the format: "Wed Sep 21 10:27:52 2011"
 */
std::string toAsciiTimeUTC(const struct tm* tm_time);

/**
 * @brief Getter for the current time, in a human-readable format.
 *
 * @return the current date/time in the format: "Wed Sep 21 10:27:52 2011"
 */
std::string getAsciiTime();

}
