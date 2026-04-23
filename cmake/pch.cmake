# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

# Precompiled-header support for osquery.
#
# osqueryPCHFile() returns (via PARENT_SCOPE) the absolute path to the PCH
# header file (cmake/osquery_pch.h).  Using a real .h file instead of
# angle-bracket system-header tokens lets CMake compile separate PCH
# artifacts for CXX and OBJCXX via $<COMPILE_LANGUAGE:> generator
# expressions, avoiding the Clang "Objective-C was disabled in PCH file"
# mismatch for .mm translation units.
#
# Headers were chosen based on ClangBuildAnalyzer output: each contributed
# hundreds of seconds of cumulative parse time across the codebase.
#
# Usage: applied automatically by add_osquery_library() to every non-INTERFACE,
# non-IMPORTED static/shared/object library.

function(osqueryPCHFile out_var)
  set(${out_var} "${CMAKE_SOURCE_DIR}/cmake/osquery_pch.h" PARENT_SCOPE)
endfunction()
