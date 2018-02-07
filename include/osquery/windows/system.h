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

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>

/// We define SIGHUP similarly to POSIX.
#define SIGHUP 1

// Windows defines the function GetObject globally meaning when compiling on
// Windows, cl doesn't know what function to use. We need to undef this at the
// beginning of all files that try to call the RapidJSON GetObject
#undef GetObject

/**
 * @brief For Windows, SIGILL and SIGTERM are not generated signals.
 *
 * To supplant the SIGUSR1 use-case on POSIX, we use SIGILL.
 */
#define SIGUSR1 SIGILL
#define SIGALRM SIGUSR1

namespace osquery {
/**
 * @brief Microsoft provides FUNCTION_s with more or less the same parameters.
 *
 * Notice that they are swapped when compared to POSIX FUNCTION_r.
 */
struct tm* gmtime_r(time_t* t, struct tm* result);

/// See gmtime_r.
struct tm* localtime_r(time_t* t, struct tm* result);

void alarm(int /* noop */);

/// Unfortunately, pid_t is not defined in Windows, however, DWORD is the
/// most appropriate alternative since process ID on Windows are stored in
/// a DWORD.
using pid_t = unsigned long;
using PlatformPidType = void*;
} // namespace osquery
