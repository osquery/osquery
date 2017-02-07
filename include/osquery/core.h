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

#include <csignal>
#include <memory>
#include <shared_mutex>
#include <string>
#include <vector>

#include <osquery/status.h>

// clang-format off
#ifndef STR
#define STR_OF(x) #x
#define STR(x) STR_OF(x)
#endif

#ifdef WIN32
#define STR_EX(...) __VA_ARGS__
#else
#define STR_EX(x) x
#endif
#define CONCAT(x, y) STR(STR_EX(x)STR_EX(y))

#ifndef FRIEND_TEST
#define FRIEND_TEST(test_case_name, test_name) \
  friend class test_case_name##_##test_name##_Test
#endif
// clang-format on

#ifdef WIN32
#define USED_SYMBOL
#define EXPORT_FUNCTION __declspec(dllexport)
#else
#define USED_SYMBOL __attribute__((used))
#define EXPORT_FUNCTION
#endif

/**
 * @brief Platform specific code isolation and define-based conditionals.
 *
 * The following preprocessor defines are expected to be available for all
 * osquery code. Please use them sparingly and prefer the run-time detection
 * methods first. See the %PlatformType class and %isPlatform method.
 *
 * OSQUERY_BUILD_PLATFORM: For Linux, this is the distro name, for OS X this is
 *   darwin, and on Windows it is windows. The set of potential values comes
 *   the ./tools/platform scripts and may be overridden.
 * OSQUERY_BUILD_DISTRO: For Linux, this is the version, for OS X this is the
 *   version (10.10, 10.11, 10.12), for Windows this is Win10.
 *
 * OSQUERY_BUILD_VERSION: available as kVersion, the version of osquery.
 * OSQUERY_SDK_VERSION: available as kSDKVersion, the most recent tag.
 * OSQUERY_PLATFORM: available as kSDKPlatform, a OSQUERY_BUILD_PLATFORM string.
 * OSQUERY_PLATFORM_MASK: a mask of platform features for runtime detection.
 *   See below for PlatformDetector-related methods.
 */
#if !defined(OSQUERY_BUILD_SDK_VERSION)
#error The build must define OSQUERY_BUILD_SDK_VERSION.
#elif !defined(OSQUERY_BUILD_PLATFORM)
#error The build must define OSQUERY_BUILD_PLATFORM.
#elif !defined(OSQUERY_BUILD_DISTRO)
#error The build must define OSQUERY_BUILD_DISTRO.
#endif

/// Use a macro for the sdk/platform literal, symbols available in lib.cpp.
#define OSQUERY_SDK_VERSION STR(OSQUERY_BUILD_SDK_VERSION)
#define OSQUERY_PLATFORM STR(OSQUERY_BUILD_PLATFORM)

/**
 * @brief A series of platform-specific home folders.
 *
 * There are several platform-specific folders where osquery reads and writes
 * content. Most of the variance is due to legacy support.
 *
 * OSQUERY_HOME: Configuration, flagfile, extensions and module autoload.
 * OSQUERY_DB_HOME: Location of RocksDB persistent storage.
 * OSQUERY_LOG_HOME: Location of log data when the filesystem plugin is used.
 */
#if defined(__linux__)
#define OSQUERY_HOME "/etc/osquery"
#define OSQUERY_DB_HOME "/var/osquery"
#define OSQUERY_SOCKET OSQUERY_DB_HOME "/"
#define OSQUERY_LOG_HOME "/var/log/osquery/"
#define OSQUERY_CERTS_HOME "/var/osquery/certs/"
#elif defined(WIN32)
#define OSQUERY_HOME "\\ProgramData\\osquery"
#define OSQUERY_DB_HOME OSQUERY_HOME
#define OSQUERY_SOCKET "\\\\.\\pipe\\"
#define OSQUERY_LOG_HOME "\\ProgramData\\osquery\\log\\"
#define OSQUERY_CERTS_HOME "\\ProgramData\\osquery\\certs\\"
#else
#define OSQUERY_HOME "/var/osquery"
#define OSQUERY_DB_HOME OSQUERY_HOME
#define OSQUERY_SOCKET OSQUERY_DB_HOME "/"
#define OSQUERY_LOG_HOME "/var/log/osquery/"
#define OSQUERY_CERTS_HOME "/usr/local/share/osquery/certs/"
#endif

/// A configuration error is catastrophic and should exit the watcher.
#define EXIT_CATASTROPHIC 78

namespace osquery {

/**
 * @brief A helpful tool type to report when logging, print help, or debugging.
 *
 * The Initializer class attempts to detect the ToolType using the tool name
 * and some compile time options.
 */
enum class ToolType {
  UNKNOWN = 0,
  SHELL,
  DAEMON,
  TEST,
  EXTENSION,
};

/**
 * @brief A helpful runtime-detection enumeration of platform configurations.
 *
 * CMake, or the build tooling, will generate a OSQUERY_PLATFORM_MASK and pass
 * it to the library compile only.
 */
enum class PlatformType {
  TYPE_POSIX = 0x01,
  TYPE_WINDOWS = 0x02,
  TYPE_BSD = 0x04,
  TYPE_LINUX = 0x08,
  TYPE_OSX = 0x10,
  TYPE_FREEBSD = 0x20,
};

inline PlatformType operator|(PlatformType a, PlatformType b) {
  return static_cast<PlatformType>(static_cast<int>(a) | static_cast<int>(b));
}

/// The version of osquery, includes the git revision if not tagged.
extern const std::string kVersion;

/// The SDK version removes any git revision hash (1.6.1-g0000 becomes 1.6.1).
extern const std::string kSDKVersion;

/**
 * @brief Compare osquery SDK/extenion/core version strings.
 *
 * SDK versions are in major.minor.patch-commit-hash form. We provide a helper
 * method for performing version comparisons to allow gating and compatibility
 * checks throughout the code.
 *
 * @param v version to check
 * @param sdk (optional) the SDK version to check against.
 * return true if the input version is at least the SDK version.
 */
bool versionAtLeast(const std::string& v, const std::string& sdk = kSDKVersion);

/// Identifies the build platform of either the core extension.
extern const std::string kSDKPlatform;

/// The osquery tool type for runtime decisions.
extern ToolType kToolType;

/// The build-defined set of platform types.
extern const PlatformType kPlatformType;

/// Helper method for platform type detection.
inline bool isPlatform(PlatformType a, const PlatformType& t = kPlatformType) {
  return (static_cast<int>(t) & static_cast<int>(a)) != 0;
}

/// Helper alias for defining mutexes.
using Mutex = std::shared_timed_mutex;

/// Helper alias for write locking a mutex.
using WriteLock = std::unique_lock<Mutex>;

/// Helper alias for read locking a mutex.
using ReadLock = std::shared_lock<Mutex>;

/// Helper alias for defining recursive mutexes.
using RecursiveMutex = std::recursive_mutex;

/// Helper alias for write locking a recursive mutex.
using RecursiveLock = std::lock_guard<std::recursive_mutex>;
}
