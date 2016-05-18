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

#include <string>
#include <vector>

#ifdef WIN32
#define WINVER 0x0a00
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include <boost/optional.hpp>

namespace osquery {

#ifdef WIN32
using mode_t = int;
using PlatformHandle = HANDLE;

/// Windows does not define these, X_OK on Windows just ensures that the
/// file is readable.
#define F_OK 0
#define R_OK 4
#define W_OK 2
#define X_OK R_OK

const std::string kFallbackHomeDirectory = "/tmp/osquery";
#else
using PlatformHandle = int;

const std::string kFallbackHomeDirectory = "\\ProgramData\\osquery";
#endif

/// Constant for an invalid handle
const PlatformHandle kInvalidHandle = (PlatformHandle)-1;

/**
 * @brief
 *
 *
 */
class PlatformFile;

/**
 * @brief
 *
 *
 */
boost::optional<std::string> getHomeDirectory();

/**
* @brief
*
*
*/
bool platformChmod(const std::string& path, mode_t perms);

/**
* @brief
*
*
*/
std::vector<std::string> platformGlob(std::string find_path);

/**
* @brief
*
*
*/
int platformAccess(const std::string& path, int mode);
}