/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#endif

#include <osquery/utils/status/status.h>
#include <string>

namespace osquery {

/// Returns a C++ string explaining the errnum
std::string platformStrerr(int errnum);

#ifdef WIN32
/// Converts a Windows error (winerror.h/GetLastError()) to a string
Status getWindowsErrorDescription(std::wstring& error_message, DWORD error_id);
#endif

} // namespace osquery
