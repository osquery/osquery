/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <string>

#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#endif

#include <osquery/status.h>

namespace osquery {

/// Safer way to do realpath
const std::string canonicalize_file_name(const char* name);

#ifdef WIN32
/// Converts a Windows error (winerror.h/GetLastError()) to a string
Status getWindowsErrorDescription(std::string& error_message, DWORD error_id);
#endif
}
