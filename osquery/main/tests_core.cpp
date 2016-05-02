/*
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under the BSD-style license found in the
*  LICENSE file in the root directory of this source tree. An additional grant
*  of patent rights can be found in the PATENTS file in the same directory.
*
*/

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Shlwapi.h>
#endif

#include <gtest/gtest.h>

#include <osquery/logger.h>

#include "osquery/core/process.h"
#include "osquery/core/test_util.h"

#define OSQUERY_TESTS_MODULENAME  "osquery_tests.exe"

char *self_exec_path = nullptr;

const char *expected_worker_args[] = {
  "worker-test"
};
const char *expected_extension_args[] = {
  "osquery extension: extension-test",
  "--socket",
  "socket-name",
  "--timeout",
  "100",
  "--interval",
  "5",
  "--verbose"
};

bool compareArguments(char *result[],
  unsigned int result_nelms,
  const char *expected[],
  unsigned int expected_nelms) {
  if (result_nelms != expected_nelms) {
    return false;
  }

  for (unsigned int i = 0; i < expected_nelms; i++) {
    if (strlen(result[i]) != strlen(expected[i])) {
      return false;
    }

    if (strncmp(result[i], expected[i], strlen(expected[i])) != 0) {
      return false;
    }
  }

  return true;
}

int workerMain(int argc, char *argv[]) {
  if (!compareArguments(argv,
    argc,
    expected_worker_args,
    sizeof(expected_worker_args) / sizeof(const char *))) {
    return -1;
  }

  osquery::PlatformProcess process = osquery::getLauncherProcess();
  if (!process.isValid()) {
    return -2;
  }

#ifdef WIN32
  CHAR buffer[1024] = { 0 };
  DWORD size = 1024;
  if (!QueryFullProcessImageNameA(process.nativeHandle(),
    0,
    buffer,
    &size)) {
    return -3;
  }
  PathStripPathA(buffer);

  if (strlen(buffer) != strlen(OSQUERY_TESTS_MODULENAME)) {
    return -4;
  }

  if (strncmp(buffer, OSQUERY_TESTS_MODULENAME, strlen(buffer)) != 0) {
    return -5;
  }
#else
  if (process.nativeHandle() != getppid()) {
    return -3;
  }
#endif
  return WORKER_SUCCESS_CODE;
}

int extensionMain(int argc, char *argv[]) {
  if (!compareArguments(argv,
    argc,
    expected_extension_args,
    sizeof(expected_extension_args) / sizeof(const char *))) {
    return -1;
  }
  return EXTENSION_SUCCESS_CODE;
}

int main(int argc, char* argv[]) {
  if (auto val = osquery::getEnvVar("OSQUERY_WORKER")) {
    return workerMain(argc, argv);
  } else if ((val = osquery::getEnvVar("OSQUERY_EXTENSIONS"))) {
    return extensionMain(argc, argv);
  }
  self_exec_path = argv[0];

  osquery::initTesting();
  testing::InitGoogleTest(&argc, argv);
  // Optionally enable Goggle Logging
  // google::InitGoogleLogging(argv[0]);
  auto result = RUN_ALL_TESTS();

  osquery::shutdownTesting();
  return result;
}