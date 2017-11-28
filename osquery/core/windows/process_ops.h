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

#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN
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
* @brief Get the relative identifier (RID) from a security identifier (SID).
*
* @returns the RID represented as an unsigned long integer.
*/
unsigned long getRidFromSid(PSID sidPtr);
}