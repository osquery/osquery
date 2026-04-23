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

#include <algorithm>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
