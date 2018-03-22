/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#ifndef WIN32
#include <sys/wait.h>
#endif

#include <gtest/gtest.h>

#include <osquery/core.h>

#include "osquery/core/process.h"
#include "osquery/tests/test_util.h"

namespace osquery {

/// Unlike checkChildProcessStatus, this will block until process exits.
static bool getProcessExitCode(osquery::PlatformProcess& process,
                               int& exitCode) {
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
  int status {0};
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
  EXPECT_NE(handle, reinterpret_cast<HANDLE>(nullptr));

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

  auto process = PlatformProcess::getCurrentProcess();
  EXPECT_NE(nullptr, process.get());

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
  EXPECT_FALSE(val.is_initialized());

  EXPECT_TRUE(setEnvVar("GTEST_OSQUERY", "true"));

  val = getEnvVar("GTEST_OSQUERY");
  EXPECT_FALSE(!val);
  EXPECT_TRUE(val.is_initialized());
  EXPECT_EQ(*val, "true");

  EXPECT_TRUE(unsetEnvVar("GTEST_OSQUERY"));

  val = getEnvVar("GTEST_OSQUERY");
  EXPECT_FALSE(val);
  EXPECT_FALSE(val.is_initialized());
}

TEST_F(ProcessTests, test_launchExtension) {
  {
    auto process =
        PlatformProcess::launchExtension(kProcessTestExecPath.c_str(),
                                         kExpectedExtensionArgs[3],
                                         kExpectedExtensionArgs[5],
                                         kExpectedExtensionArgs[7],
                                         true);
    EXPECT_NE(nullptr, process.get());

    int code {0};
    EXPECT_TRUE(getProcessExitCode(*process, code));
    EXPECT_EQ(code, EXTENSION_SUCCESS_CODE);
  }
}

TEST_F(ProcessTests, test_launchWorker) {
  {
    std::vector<char*> argv;
    for (size_t i = 0; i < kExpectedWorkerArgsCount; i++) {
      char* entry = new char[strlen(kExpectedWorkerArgs[i]) + 1];
      EXPECT_NE(entry, nullptr);
      memset(entry, '\0', strlen(kExpectedWorkerArgs[i]) + 1);
      memcpy(entry, kExpectedWorkerArgs[i], strlen(kExpectedWorkerArgs[i]));
      argv.push_back(entry);
    }
    argv.push_back(nullptr);

    auto process = PlatformProcess::launchWorker(
        kProcessTestExecPath.c_str(),
        static_cast<int>(kExpectedWorkerArgsCount),
        &argv[0]);
    for (size_t i = 0; i < argv.size(); i++) {
      delete[] argv[i];
    }

    EXPECT_NE(nullptr, process.get());

    int code {0};
    EXPECT_TRUE(getProcessExitCode(*process, code));
    EXPECT_EQ(code, WORKER_SUCCESS_CODE);
  }
}
}
