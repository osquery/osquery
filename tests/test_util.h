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
#include <utility>
#include <vector>

#include <osquery/config/config.h>
#include <osquery/core/core.h>
#include <osquery/database/database.h>
#include <osquery/events/eventsubscriberplugin.h>
#include <osquery/filesystem/filesystem.h>

namespace osquery {
/// The following codes are specifically for checking whether the child worker
/// or extension process ran successfully. These values should be the values
/// captured as exit codes if all the child process checks complete without
/// deviation.
#define EXTENSION_SUCCESS_CODE 0x45
#define WORKER_SUCCESS_CODE 0x57

/// The following are error codes returned by the child process.
#define ERROR_COMPARE_ARGUMENT (-1)
#define ERROR_LAUNCHER_PROCESS (-2)
#define ERROR_QUERY_PROCESS_IMAGE (-3)
#define ERROR_IMAGE_NAME_LENGTH (-4)
#define ERROR_LAUNCHER_MISMATCH (-5)

/// Init function for tests and benchmarks.
void initTesting();

/// Cleanup/stop function for tests and benchmarks.
void shutdownTesting();

/// A fake directory tree should be used for filesystem iterator testing.
const std::string kFakeDirectoryName{"fstree"};

/// Tests can be run from within the source or build directory.
/// The test initializer will attempt to discovery the current working path.
extern std::string kTestDataPath;

/// Tests should limit intermediate input/output to a working directory.
/// Config data, logging results, and intermediate database/caching usage.
extern std::string kTestWorkingDirectory;
extern std::string kFakeDirectory;

/// Stores the path of the currently executing executable
extern std::string kProcessTestExecPath;

/// This is the expected module name of the launcher process.
extern const char* kOsqueryTestModuleName;

/// These are the expected arguments for our test worker process.
extern const char* kExpectedWorkerArgs[];
extern const size_t kExpectedWorkerArgsCount;

/// These are the expected arguments for our test extensions process.
extern const char* kExpectedExtensionArgs[];
extern const size_t kExpectedExtensionArgsCount;

ScheduledQuery getOsqueryScheduledQuery();

// Helper function to generate all rows from a generator-based table.
TableRows genRows(EventSubscriberPlugin* sub);

#ifdef OSQUERY_WINDOWS
void initUsersAndGroupsServices(bool init_users, bool init_groups);
void deinitUsersAndGroupsServices(bool deinit_users, bool deinit_groups);
#endif

} // namespace osquery
