/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>

#include <osquery/utils/info/version.h>
#include <osquery/utils/macros/macros.h>

namespace osquery {

/**
 * @brief A helpful runtime-detection enumeration of platform configurations.
 *
 * CMake, or the build tooling, will generate a OSQUERY_PLATFORM_MASK and pass
 * it to the library compile only.
 *
 * This information is exposed through the osquery_info table. Be cautious
 * changing values.
 */
enum class PlatformType {
  TYPE_POSIX = 0x01,
  TYPE_WINDOWS = 0x02,
  TYPE_BSD = 0x04,
  TYPE_LINUX = 0x08,
  TYPE_OSX = 0x10,
  TYPE_FREEBSD = 0x20,
};

/// The build-defined set of platform types.
constexpr PlatformType kPlatformType = static_cast<PlatformType>(0u
#ifdef POSIX
    | static_cast<unsigned>(PlatformType::TYPE_POSIX)
#endif
#ifdef WINDOWS
    | static_cast<unsigned>(PlatformType::TYPE_WINDOWS)
#endif
#ifdef BSD
    | static_cast<unsigned>(PlatformType::TYPE_BSD)
#endif
#ifdef LINUX
    | static_cast<unsigned>(PlatformType::TYPE_LINUX)
#endif
#ifdef DARWIN
    | static_cast<unsigned>(PlatformType::TYPE_OSX)
#endif
#ifdef FREEBSD
    | static_cast<unsigned>(PlatformType::TYPE_FREEBSD)
#endif
);

bool isPlatform(PlatformType a, const PlatformType& t = kPlatformType);

PlatformType operator|(PlatformType a, PlatformType b);

/**
 * @brief Platform specific code isolation and define-based conditionals.
 *
 * The following preprocessor defines are expected to be available for all
 * osquery code. Please use them sparingly and prefer the run-time detection
 * methods first. See the %PlatformType class and %isPlatform method.
 *
 * OSQUERY_BUILD_PLATFORM: For Linux, this is the distro name, for macOS this is
 *   darwin, and on Windows it is windows. The set of potential values comes
 *   the ./tools/platform scripts and may be overridden.
 * OSQUERY_BUILD_DISTRO: For Linux, this is the version, for macOS this is the
 *   version (10.14, 10.15, etc.), for Windows this is Win10.
 * OSQUERY_PLATFORM: available as kSDKPlatform, a OSQUERY_BUILD_PLATFORM string.
 */
#if !defined(OSQUERY_BUILD_PLATFORM)
#error The build must define OSQUERY_BUILD_PLATFORM.
#endif

#if !defined(OSQUERY_BUILD_DISTRO)
#error The build must define OSQUERY_BUILD_DISTRO.
#endif

#define OSQUERY_PLATFORM OSQUERY_BUILD_PLATFORM

/// Identifies the build platform of either the core extension.
extern const std::string kSDKPlatform;

} // namespace osquery
