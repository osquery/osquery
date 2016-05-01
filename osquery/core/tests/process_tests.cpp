/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
 
#include <osquery/core.h>
#include <gtest/gtest.h>

#ifdef WIN32
#include <Shlwapi.h>
#endif

#include "osquery/core/process.h"

extern char *self_exec_path;

bool getProcessExitCode(osquery::PlatformProcess& process, int& exitCode)
{
  if (!process.isValid()) {
    return false;
  }

#ifdef WIN32
  DWORD code = 0;
  DWORD ret = 0;

  while ((ret = ::WaitForSingleObject(process.nativeHandle(), INFINITE)) != WAIT_FAILED &&
    ret != WAIT_OBJECT_0);
  if (ret == WAIT_FAILED) {
    return false;
  }

  if (!::GetExitCodeProcess(process.nativeHandle(), &code)) {
    return false;
  }

  if (code != STILL_ACTIVE) {
    exitCode = code;
    return true;
  }
#else
  int status = 0;
  if (::waitpid(process.nativeHandle(), &status, 0) == -1) {
    return false;
  }
  if (WIFEXITED(status)) {
    exitCode = WEXITSTATUS(status);
    return true;
  }
#endif
  return false;
}

#define EXTENSION_SUCCESS_CODE  0x45
#define WORKER_SUCCESS_CODE     0x57

#define OSQUERY_TESTS_MODULENAME  "osquery_tests.exe"

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

  for (int i = 0; i < expected_nelms; i++) {
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

namespace osquery {

class ProcessTests : public testing::Test {};

TEST_F(ProcessTests, test_constructor) {
  auto p = PlatformProcess(kInvalidPid);
  EXPECT_FALSE(p.isValid());
}

#ifdef WIN32
TEST_F(ProcessTests, test_constructorWin) {
  HANDLE handle = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, ::GetCurrentProcessId());
  EXPECT_NE(handle, reinterpret_cast<HANDLE>(NULL));
  
  auto p = PlatformProcess(handle);
  EXPECT_TRUE(p.isValid());
  EXPECT_NE(p.nativeHandle(), handle);
  
  ::CloseHandle(handle);
}
#else
TEST_F(ProcessTests, test_constructorPosix) {
  auto p = PlatformProcess(getpid());
  EXPECT_TRUE(p.isValid());
  EXPECT_EQ(p.nativeHandle(), getpid());
}
#endif

TEST_F(ProcessTests, test_envVar) {
  auto val = getEnvVar("GTEST_OSQUERY");
  EXPECT_FALSE(val);
  
  EXPECT_TRUE(setEnvVar("GTEST_OSQUERY", "true"));
  
  val = getEnvVar("GTEST_OSQUERY");
  EXPECT_EQ(*val, "true");
  
  EXPECT_TRUE(unsetEnvVar("GTEST_OSQUERY"));
  
  val = getEnvVar("GTEST_OSQUERY");
  EXPECT_FALSE(val);
}

TEST_F(ProcessTests, test_launchExtension) {
  // We are assuming fasdgasdglhasjldgbaousgd9uasbdf is not a valid process name...
  {
    osquery::PlatformProcess process = osquery::PlatformProcess::launchExtension(
      "fasdgasdglhasjldgbaousgd9uasbdf",
      "extension-test",
      "socket-name",
      "100",
      "5",
      "true"
    );
    EXPECT_FALSE(process.isValid());
  }

  {
    osquery::PlatformProcess process = osquery::PlatformProcess::launchExtension(
      self_exec_path,
      "extension-test",
      "socket-name",
      "100",
      "5",
      "true"
    );
    EXPECT_TRUE(process.isValid());

    int code = 0;
    EXPECT_TRUE(getProcessExitCode(process, code));
    EXPECT_EQ(code, EXTENSION_SUCCESS_CODE);
  }
}

TEST_F(ProcessTests, test_launchWorker) {
  {
    // Assuming fasdgasdglhasjldgbaousgd9uasbdf is not a valid process
    osquery::PlatformProcess process = osquery::PlatformProcess::launchWorker(
      "fasdgasdglhasjldgbaousgd9uasbdf",
      "worker-test"
    );
    EXPECT_FALSE(process.isValid());
  }

  {
    osquery::PlatformProcess process = osquery::PlatformProcess::launchWorker(
      self_exec_path,
      "worker-test"
    );
    EXPECT_TRUE(process.isValid());

    int code = 0;
    EXPECT_TRUE(getProcessExitCode(process, code));
    EXPECT_EQ(code, WORKER_SUCCESS_CODE);
  }
}
}