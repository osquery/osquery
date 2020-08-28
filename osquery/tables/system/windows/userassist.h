/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
namespace osquery {
namespace tables {

// Decode ROT13 data
std::string rotDecode(std::string& value_key_reg);

// Get Epoch time from Windows FILETIME in little endian format
// Windows Registry sometimes stores FILETIME in little endian format
long long littleEndianToUnixTime(const std::string& time_data);
} // namespace tables
} // namespace osquery
