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

#include <ctime>

#ifndef NOMINMAX
#define NOMINMAX
#endif

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

/// We define SIGHUP similarly to POSIX.
#define SIGHUP 1

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
