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

} // namespace osquery