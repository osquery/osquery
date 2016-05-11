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

/// The following codes are specifically for checking whether the child worker
/// or extension process ran successfully. These values should be the values
/// captured as exit codes if all the child process checks complete without
/// deviation.
#define EXTENSION_SUCCESS_CODE 0x45
#define WORKER_SUCCESS_CODE 0x57

/// The following are error codes returned by the child process.
#define ERROR_COMPARE_ARGUMENT -1
#define ERROR_LAUNCHER_PROCESS -2
#define ERROR_QUERY_PROCESS_IMAGE -3
#define ERROR_IMAGE_NAME_LENGTH -4
#define ERROR_LAUNCHER_MISMATCH -5

namespace osquery {

/// Stores the path of the currently executing executable
extern std::string kProcessTestExecPath;

/// This is the expected module name of the launcher process.
extern const char *kOsqueryTestModuleName;

/// These are the expected arguments for our test worker process.
extern const char *kExpectedWorkerArgs[];

/// These are the expected arguments for our test extensions process.
extern const char *kExpectedExtensionArgs[];
}

