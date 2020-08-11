/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <ctime>

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <SdkDdkVer.h>

#ifndef NTDDI_VERSION
#error "NTDDI_VERSION must be defined, see tools/build_defs/oss/osquery/cxx.bzl"
#endif

#ifndef _WIN32_WINNT
#error "_WIN32_WINNT must be defined, see tools/build_defs/oss/osquery/cxx.bzl"
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef _WIN32_DCOM
#define _WIN32_DCOM
#endif

#include <windows.h>

/// We define SIGHUP similarly to POSIX.
#define SIGHUP 1

// Windows defines the function GetObject globally meaning when compiling on
// Windows, cl doesn't know what function to use. We need to undef this at the
// beginning of all files that try to call the RapidJSON GetObject
#undef GetObject
#undef GetMessage

/**
 * @brief For Windows, SIGILL and SIGTERM are not generated signals.
 *
 * To supplant the SIGUSR1 use-case on POSIX, we use SIGILL.
 */
#define SIGUSR1 SIGILL
#define SIGALRM SIGUSR1

// Also let's include some other windows headers as far it depends on the
// include order and macrodefinitions to set it up. To make sure windows API has
// consistent setting we do it in one place.

#include <Sysinfoapi.h>

// Suppressing unexpected token following preprocessor directive warning
#pragma warning(push, 3)
#pragma warning(disable : 4067)
#include <sddl.h>
#pragma warning(pop)

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
