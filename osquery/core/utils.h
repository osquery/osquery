/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <string>

#include <boost/optional.hpp>

#include <osquery/core.h>

namespace osquery {

/// Returns the ASCII version of the timeptr as a C++ string
std::string platformAsctime(const struct tm* timeptr);

/// Converts a UTC epoch into a struct tm*
Status platformGmtime(const size_t epoch, struct tm* result);

/// Returns a C++ string explaining the errnum
std::string platformStrerr(int errnum);

/// Copies src string into the dst string buffer with error checks
Status platformStrncpy(char* dst, size_t nelms, const char* src, size_t count);
}
