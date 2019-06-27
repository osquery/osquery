/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <codecvt>
#include <string>

#include <comutil.h>

namespace osquery {

/**
 * @brief Windows helper function for converting narrow strings to wide
 *
 * @returns A wide string, constructed from a narrow string
 */
std::wstring stringToWstring(const std::string& src);

/**
 * @brief Windows helper function for converting wide strings to narrow
 *
 * @returns A narrow string, constructed from a wide string
 */
std::string wstringToString(const wchar_t* src);

/**
 * @brief Windows WMI Helper function to print the type associated with results
 *
 * @returns A string created from a BSTR
 */
std::string bstrToString(const BSTR src);

} // namespace osquery
