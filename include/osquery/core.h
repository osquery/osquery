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
#include <mutex>
#include <string>
#include <vector>

#include <osquery/status.h>

// clang-format off
#ifndef STR
#define STR_OF(x) #x
#define STR(x) STR_OF(x)
#endif
#define STR_EX(x) x
#define CONCAT(x, y) STR(STR_EX(x)STR_EX(y))

#ifndef FRIEND_TEST
#define FRIEND_TEST(test_case_name, test_name) \
  friend class test_case_name##_##test_name##_Test
#endif
// clang-format on

#ifdef WIN32
#define USED_SYMBOL
#else
#define USED_SYMBOL __attribute__((used))
#endif

#if defined(__linux__)
#define OSQUERY_HOME "/etc/osquery"
#define OSQUERY_DB_HOME "/var/osquery"
#define OSQUERY_LOG_HOME "/var/log/osquery/"
#elif defined(WIN32)
#define OSQUERY_HOME "\\ProgramData\\osquery"
#define OSQUERY_DB_HOME OSQUERY_HOME
#define OSQUERY_LOG_HOME "\\ProgramData\\osquery\\log\\"
#else
#define OSQUERY_HOME "/var/osquery"
#define OSQUERY_DB_HOME OSQUERY_HOME
#define OSQUERY_LOG_HOME "/var/log/osquery/"
#endif

/// A configuration error is catastrophic and should exit the watcher.
#define EXIT_CATASTROPHIC 78

namespace osquery {

/// The version of osquery, includes the git revision if not tagged.
extern const std::string kVersion;

/// The SDK version removes any git revision hash (1.6.1-g0000 becomes 1.6.1).
extern const std::string kSDKVersion;

/// Identifies the build platform of either the core extension.
extern const std::string kSDKPlatform;

/// Use a macro for the sdk/platform literal, symbols available in lib.cpp.
#define OSQUERY_SDK_VERSION STR(OSQUERY_BUILD_SDK_VERSION)
#define OSQUERY_PLATFORM STR(OSQUERY_BUILD_PLATFORM)

/**
 * @brief A helpful tool type to report when logging, print help, or debugging.
 */
enum ToolType {
  OSQUERY_TOOL_UNKNOWN = 0,
  OSQUERY_TOOL_SHELL,
  OSQUERY_TOOL_DAEMON,
  OSQUERY_TOOL_TEST,
  OSQUERY_EXTENSION,
};

/// Helper alias for defining mutexes throughout the codebase.
using Mutex = std::mutex;

/// Helper alias for write locking a mutex.
using WriteLock = std::lock_guard<Mutex>;

/// Helper alias for read locking a mutex (do not support a ReadMutex).
// using ReadLock = std::shared_lock<std::shared_mutex>;

/// The osquery tool type for runtime decisions.
extern ToolType kToolType;

struct InitializerInterface {
  virtual const char *id() const = 0;
  virtual void run() const = 0;
  virtual ~InitializerInterface(){};
};

extern void registerRegistry(InitializerInterface *const item);
extern void registerPlugin(InitializerInterface *const item);
extern void beginRegistryAndPluginInit();
}
