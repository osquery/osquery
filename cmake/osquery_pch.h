/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Precompiled header for osquery.
//
// This file is compiled as both CXX and OBJCXX (Objective-C++) via
// per-language generator expressions in add_osquery_library(). Using a real
// .h file (rather than angle-bracket system header tokens) is required so
// that CMake can produce separate PCH artifacts for each language without
// Clang complaining about an ObjC mode mismatch.
//
// Headers were chosen based on ClangBuildAnalyzer output: each contributed
// hundreds of seconds of cumulative parse time across the codebase.

#pragma once

// On Windows/MSVC, _USE_MATH_DEFINES must be set before the first inclusion
// of <cmath> (or any header that pulls it in transitively) to expose M_PI and
// related constants.  Because the PCH is force-included before every
// translation unit's own #defines, this define must live here rather than in
// individual source files.
#ifdef _WIN32
#ifndef _USE_MATH_DEFINES
#define _USE_MATH_DEFINES
#endif
#endif

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <deque>
#include <functional>
#include <istream>
#include <locale>
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
