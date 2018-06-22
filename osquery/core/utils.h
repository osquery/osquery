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

#include <string>

#include <boost/optional.hpp>

#include <osquery/core.h>
#include <osquery/status.h>

namespace osquery {

class Status;

/// Returns the ASCII version of the timeptr as a C++ string
std::string platformAsctime(const struct tm* timeptr);

/// Returns a C++ string explaining the errnum
std::string platformStrerr(int errnum);

/// Copies src string into the dst string buffer with error checks
Status platformStrncpy(char* dst, size_t nelms, const char* src, size_t count);

#ifdef OSQUERY_POSIX
/// Safer way to do realpath
const std::string canonicalize_file_name(const char* name);
#endif
}
