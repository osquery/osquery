/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#ifdef WIN32

#include <Shlwapi.h>
#include <osquery/utils/system/system.h>
#endif

#include <memory>

#include <gtest/gtest.h>

#include <osquery/logger/logger.h>
#include <osquery/process/process.h>

#include "osquery/tests/test_util.h"

namespace osquery {

/// This is exposed for process_tests.cpp. Without exporting this variable, we
/// would need to use more complicated measures to determine the current
/// executing file's path.
std::string kProcessTestExecPath;

/// This is the expected module name of the launcher process.
const char* kOsqueryTestModuleName = "osquery_tests.exe";

/// These are the expected arguments for our test worker process.
const char* kExpectedWorkerArgs[] = {
    nullptr, "--socket", "fake-socket", nullptr};
const size_t kExpectedWorkerArgsCount =
    (sizeof(osquery::kExpectedWorkerArgs) / sizeof(char*)) - 1;

/// These are the expected arguments for our test extensions process.
const char* kExpectedExtensionArgs[] = {nullptr,
                                        "--verbose",
                                        "--socket",
                                        "socket-name",
                                        "--timeout",
                                        "100",
                                        "--interval",
                                        "5",
                                        nullptr};
const size_t kExpectedExtensionArgsCount =
    (sizeof(osquery::kExpectedExtensionArgs) / sizeof(char*)) - 1;

static bool compareArguments(char* result[],
                             unsigned int result_nelms,
                             const char* expected[],
                             unsigned int expected_nelms) {
  if (result_nelms != expected_nelms) {
    return false;
  }

  for (size_t i = 0; i < expected_nelms; i++) {
    if (strlen(result[i]) != strlen(expected[i])) {
      return false;
    }

    if (strncmp(result[i], expected[i], strlen(expected[i])) != 0) {
      return false;
    }
  }

  return true;
}
} // namespace osquery

int workerMain(int argc, char* argv[]) {
  if (!osquery::compareArguments(argv,
                                 argc,
                                 osquery::kExpectedWorkerArgs,
                                 osquery::kExpectedWorkerArgsCount)) {
    return ERROR_COMPARE_ARGUMENT;
  }

  auto process = osquery::PlatformProcess::getLauncherProcess();
  if (process == nullptr) {
    return ERROR_LAUNCHER_PROCESS;
  }

#ifdef WIN32
  CHAR buffer[1024] = {0};
  DWORD size = 1024;
  if (!QueryFullProcessImageNameA(process->nativeHandle(), 0, buffer, &size)) {
    return ERROR_QUERY_PROCESS_IMAGE;
  }
  PathStripPathA(buffer);

  if (strlen(buffer) != strlen(osquery::kOsqueryTestModuleName)) {
    return ERROR_IMAGE_NAME_LENGTH;
  }

  if (strncmp(buffer, osquery::kOsqueryTestModuleName, strlen(buffer)) != 0) {
    return ERROR_LAUNCHER_MISMATCH;
  }
#else
  if (process->nativeHandle() != getppid()) {
    return ERROR_LAUNCHER_MISMATCH;
  }
#endif
  return WORKER_SUCCESS_CODE;
}

int extensionMain(int argc, char* argv[]) {
  if (!osquery::compareArguments(argv,
                                 argc,
                                 osquery::kExpectedExtensionArgs,
                                 osquery::kExpectedExtensionArgsCount)) {
    return ERROR_COMPARE_ARGUMENT;
  }
  return EXTENSION_SUCCESS_CODE;
}

int main(int argc, char* argv[]) {
  osquery::kProcessTestExecPath = argv[0];
  osquery::kExpectedExtensionArgs[0] = argv[0];
  osquery::kExpectedWorkerArgs[0] = argv[0];

  if (auto val = osquery::getEnvVar("OSQUERY_WORKER")) {
    return workerMain(argc, argv);
  } else if ((val = osquery::getEnvVar("OSQUERY_EXTENSION"))) {
    return extensionMain(argc, argv);
  }

  osquery::initTesting();
  testing::InitGoogleTest(&argc, argv);
  // Optionally enable Goggle Logging
  // google::InitGoogleLogging(argv[0]);
  auto result = RUN_ALL_TESTS();

  osquery::shutdownTesting();
  return result;
}
