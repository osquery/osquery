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

#include <cstdint>
#include <ctime>
#include <string>

#include <osquery/status.h>

namespace osquery {

/// Returns the ASCII version of the timeptr as a C++ string
std::string platformAsctime(const struct tm* timeptr);

/// Returns a C++ string explaining the errnum
std::string platformStrerr(int errnum);

#ifdef OSQUERY_POSIX
/// Safer way to do realpath
const std::string canonicalize_file_name(const char* name);
#endif

#ifdef __APPLE__
/// Builds a list of the known BSD file flags specified by st_flags (see the
/// stat structure). Foreign bits are added to the list as a hexadecimal number
/// If undocumented bits are found inside the st_flags value, the function will
/// include them in the output as a hexadecimal value and return false.
bool describeBSDFileFlags(std::string& output, std::uint32_t st_flags);
#endif
}
