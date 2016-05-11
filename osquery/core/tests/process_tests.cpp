/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/core.h>

#include "osquery/core/process.h"
#include "osquery/core/testing.h"

namespace osquery {

/// Unlike checkChildProcessStatus, this will block until process exits.
static bool getProcessExitCode(osquery::PlatformProcess &process,
                               int &exitCode) {
  if (!process.isValid()) {
    return false;
  }

#ifdef WIN32
  DWORD code = 0;
  DWORD ret = 0;

  while ((ret = ::WaitForSingleObject(process.nativeHandle(), INFINITE)) !=
             WAIT_FAILED &&
         ret != WAIT_OBJECT_0)
    ;
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

class ProcessTests : public testing::Test {};

TEST_F(ProcessTests, test_constructor) {
  auto p = PlatformProcess(kInvalidPid);
  EXPECT_FALSE(p.isValid());
}

#ifdef WIN32
TEST_F(ProcessTests, test_constructorWin) {
  HANDLE handle =
      ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, ::GetCurrentProcessId());
  EXPECT_NE(handle, reinterpret_cast<HANDLE>(NULL));

  auto p = PlatformProcess(handle);
  EXPECT_TRUE(p.isValid());
  EXPECT_NE(p.nativeHandle(), handle);

  if (handle) {
    ::CloseHandle(handle);
  }
}
#else
TEST_F(ProcessTests, test_constructorPosix) {
  auto p = PlatformProcess(getpid());
  EXPECT_TRUE(p.isValid());
  EXPECT_EQ(p.nativeHandle(), getpid());
}
#endif

TEST_F(ProcessTests, test_getpid) {
  int pid = -1;

  std::shared_ptr<PlatformProcess> process =
      PlatformProcess::getCurrentProcess();
  EXPECT_TRUE(process.get());

#ifdef WIN32
  pid = (int)::GetCurrentProcessId();
#else
  pid = getpid();
#endif

  EXPECT_EQ(process->pid(), pid);
}

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
  {
    std::shared_ptr<osquery::PlatformProcess> process =
        osquery::PlatformProcess::launchExtension(kProcessTestExecPath.c_str(),
                                                  "extension-test",
                                                  kExpectedExtensionArgs[2],
                                                  kExpectedExtensionArgs[4],
                                                  kExpectedExtensionArgs[6],
                                                  "true");
    EXPECT_TRUE(process.get());

    int code = 0;
    EXPECT_TRUE(getProcessExitCode(*process, code));
    EXPECT_EQ(code, EXTENSION_SUCCESS_CODE);
  }
}

TEST_F(ProcessTests, test_launchWorker) {
  {
    std::shared_ptr<osquery::PlatformProcess> process =
        osquery::PlatformProcess::launchWorker(kProcessTestExecPath.c_str(),
                                               kExpectedWorkerArgs[0]);
    EXPECT_TRUE(process.get());

    int code = 0;
    EXPECT_TRUE(getProcessExitCode(*process, code));
    EXPECT_EQ(code, WORKER_SUCCESS_CODE);
  }
}

#ifdef WIN32
TEST_F(ProcessTests, test_launchExtensionQuotes) {
  {
    std::shared_ptr<osquery::PlatformProcess> process =
        osquery::PlatformProcess::launchExtension(kProcessTestExecPath.c_str(),
                                                  "exten\"sion-te\"st",
                                                  "socket-name",
                                                  "100",
                                                  "5",
                                                  "true");
    EXPECT_TRUE(process.get());

    int code = 0;
    EXPECT_TRUE(getProcessExitCode(*process, code));
    EXPECT_EQ(code, EXTENSION_SUCCESS_CODE);
  }
}

TEST_F(ProcessTests, test_launchWorkerQuotes) {
  {
    std::shared_ptr<osquery::PlatformProcess> process =
        osquery::PlatformProcess::launchWorker(kProcessTestExecPath.c_str(),
                                               "worker\"-test");
    EXPECT_TRUE(process.get());

    int code = 0;
    EXPECT_TRUE(getProcessExitCode(*process, code));
    EXPECT_EQ(code, WORKER_SUCCESS_CODE);
  }
}
#endif
}

