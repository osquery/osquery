/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/system/system.h>

#include <string>

namespace osquery {

/**
 * @brief Windows helper function for converting FILETIME to Unix epoch
 *
 * @returns The unix epoch timestamp representation of the FILETIME
 */
LONGLONG filetimeToUnixtime(const FILETIME& ft);

/**
 * @brief Windows helper function for converting LARGE INTs to Unix epoch
 *
 * @returns The unix epoch timestamp representation of the LARGE int value
 */
LONGLONG longIntToUnixtime(LARGE_INTEGER& ft);

/**
 * @brief Windows helper function for converting Little Endian FILETIME to Unix
 * epoch. Windows Registry sometimes stores FILETIME in little endian format
 *
 * @returns The unix epoch timestamp representation of the FILETIME
 */
LONGLONG littleEndianToUnixTime(const std::string& time_data);

/**
 * @brief Windows helper function for parsing and converting FAT time to Unix
 * epoch.
 *
 * @returns The unix epoch timestamp representation of FAT time
 */
LONGLONG parseFatTime(const std::string& dos_data);

/**
 * @brief Windows helper function for converting a big-endian hex FILETIME
 * string to Unix epoch. WMI sometimes returns FILETIME as a 16-character
 * hex string (e.g., on Vista/2008 for Win32_QuickFixEngineering.InstalledOn).
 *
 * @param time_data A 16-character hex string representing a FILETIME
 * @returns The unix epoch timestamp, or 0 if parsing fails
 */
LONGLONG bigEndianFiletimeToUnixTime(const std::string& time_data);

/**
 * @brief Windows helper function for parsing locale-specific date strings
 * to Unix epoch. Handles common formats seen in WMI string properties:
 * - M/D/YYYY or MM/DD/YYYY (US locale, with slashes)
 * - YYYY-MM-DD (ISO format, with dashes)
 * - D-M-YYYY or DD-MM-YYYY (European locales, with dashes)
 *
 * @param date_str A date string in one of the supported formats
 * @returns The unix epoch timestamp (at midnight UTC), or 0 if parsing fails
 */
LONGLONG parseDateToUnixTime(const std::string& date_str);

} // namespace osquery