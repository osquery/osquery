/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
std::string wstringToString(const std::wstring& src);

/**
 * @brief Windows helper function for converting wide C-strings to narrow
 *
 * @returns A narrow string, constructed from a wide C-string
 */
std::string wstringToString(const wchar_t* src);

/**
 * @brief Windows helper function to convert a CIM Datetime to Unix timestamp
 *
 * @returns Given a CIM datetime generated from a WMI query, this helper
 * function returns the equivalent Unix timestamp
 */
LONGLONG cimDatetimeToUnixtime(const std::string& src);

/**
 * @brief Windows WMI Helper function to print the type associated with results
 *
 * @returns A string created from a BSTR
 */
std::string bstrToString(const BSTR src);

/**
 * @brief Windows helper function to swap endianess of a string
 *
 * @returns The swap endianess (little endian returns big endian, vice-versa)
 */
std::string swapEndianess(const std::string& endian_string);

/**
 * @brief Windows helper function to convert error DWORD to string
 *
 * @returns The string representation of a windows error
 */
std::string errorDwordToString(DWORD errorMessageID);

} // namespace osquery
