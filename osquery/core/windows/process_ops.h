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

#define _WIN32_DCOM

#include <Windows.h>
// clang-format off
#include <LM.h>
// clang-format on

#include <vector>

#include <osquery/system.h>
#include <osquery/logger.h>

#include "osquery/core/process.h"
#include "osquery/core/windows/wmi.h"

namespace osquery {

/**
* @brief Windows helper function used by to convert a binary SID struct into a
* string.
*
* @returns string representation of the binary SID struct.
*/
std::string psidToString(PSID sid);

/**
 * @brief Windows helper function to lookup a SID from a username
 *
 * @returns a unique_ptr to a PSID
 */
std::unique_ptr<BYTE[]> getSidFromUsername(std::wstring accountName);

/**
 * @brief Get the relative identifier (RID) from a security identifier (SID).
 *
 * @returns the RID represented as an unsigned long integer.
 */
unsigned long getRidFromSid(PSID sidPtr);

} // namespace osquery
