/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#ifndef WIN32
#include <sys/wait.h>
#else
#include <Shlwapi.h>
#include <osquery/utils/system/system.h>
#endif

#include <boost/format.hpp>

#include <gtest/gtest.h>

#include <osquery/process/process.h>

#include <osquery/tests/test_util.h>

namespace osquery {

std::string kProcessTestExecPath;

/// This is the expected base name of the test process.
const char* kOsqueryTestModuleName = "osquery_core_tests_processtests-test";

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

    int code = 0;
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

    int code = 0;
    EXPECT_TRUE(getProcessExitCode(*process, code));
    EXPECT_EQ(code, WORKER_SUCCESS_CODE);
  }
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

  auto image_length = strlen(buffer);
  auto image_length_without_ext = image_length - 4;
  auto* dot_pos = strrchr(buffer, '.');

  if (image_length_without_ext < 0)
    return ERROR_IMAGE_NAME_LENGTH;

  if (image_length_without_ext != strlen(osquery::kOsqueryTestModuleName)) {
    return ERROR_IMAGE_NAME_LENGTH;
  }

  if (strncmp(buffer,
              osquery::kOsqueryTestModuleName,
              image_length_without_ext) != 0) {
    return ERROR_LAUNCHER_MISMATCH;
  }

  if (strncmp(dot_pos, ".exe", 4) != 0) {
    return ERROR_LAUNCHER_MISMATCH;
  }
#else
  const auto parent_pid = getppid();
  if (process->nativeHandle() != parent_pid) {
    return ERROR_LAUNCHER_MISMATCH;
  }
#if OSQUERY_LINUX
  auto cmdline = std::array<char, 1024>();
  {
    const auto cmdline_file_path =
        (boost::format("/proc/%d/cmdline") % parent_pid).str();
    std::ifstream cmdline_file(cmdline_file_path);
    cmdline_file.getline(cmdline.data(), 1024);
  }

  const auto* process_name = basename(cmdline.data());

  if (strlen(process_name) != strlen(osquery::kOsqueryTestModuleName)) {
    return ERROR_IMAGE_NAME_LENGTH;
  }

  if (strncmp(process_name, osquery::kOsqueryTestModuleName, 1024) != 0) {
    return ERROR_LAUNCHER_MISMATCH;
  }
#endif

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

  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
