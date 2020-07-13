/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/core.h>
#include <osquery/tables.h>
namespace osquery {
namespace tables {

// Decode ROT13 data
std::string rotDecode(std::string& value_key_reg);

// Get Epoch time from Windows FILETIME in little endian format
// Windows Registry sometimes stores FILETIME in little endian format
long long littleEndianToUnixTime(const std::string& time_data);
} // namespace tables
} // namespace osquery
