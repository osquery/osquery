/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/tables/events/linux/bpf_process_events.h>

#include <linux/ptrace.h>

namespace osquery {

namespace {

const std::vector<std::string> kCommonColumnList = {"ntime",
                                                    "tid",
                                                    "pid",
                                                    "uid",
                                                    "gid",
                                                    "cid",
                                                    "exit_code",
                                                    "probe_error",
                                                    "event",
                                                    "parent",
                                                    "path",
                                                    "cwd",
                                                    "duration"};
// clang-format off
const tob::ebpfpub::IFunctionTracer::Event::Header kBaseBPFEventHeader = {
  // timestamp (nsecs from boot)
  1234567890ULL,

  // thread id
  1001,

  // process id
  1001,

  // user id
  1000,

  // group id
  1000,

  // cgroup id
  12345ULL,

  // exit code
  0ULL,

  // probe error flag
  false
};
// clang-format on

} // namespace

class BPFProcessEventsTests : public testing::Test {};

TEST_F(BPFProcessEventsTests, initializeEventRow) {
  ISystemStateTracker::Event event{};
  event.type = ISystemStateTracker::Event::Type::Exec;
  event.bpf_header = kBaseBPFEventHeader;
  event.parent_process_id = 2;
  event.binary_path = "/usr/bin/sudo";
  event.cwd = "/home/alessandro";

  Row row;
  BPFProcessEventSubscriber::initializeEventRow(row, event);

  if (row.size() != kCommonColumnList.size()) {
    std::stringstream stream;

    stream << "Expected:";
    for (const auto& expected_column : kCommonColumnList) {
      stream << " " << expected_column;
    }

    stream << "\nFound:";
    for (const auto& p : row) {
      stream << " " << p.first;
    }

    ASSERT_EQ(row.size(), kCommonColumnList.size()) << stream.str();
  }

  for (const auto& expected_column : kCommonColumnList) {
    EXPECT_EQ(row.count(expected_column), 1U)
        << "Missing column: " << expected_column;
  }

  EXPECT_EQ(row.at("event"), "exec");
  EXPECT_EQ(row.at("ntime"), "1234567890");
  EXPECT_EQ(row.at("tid"), "1001");
  EXPECT_EQ(row.at("pid"), "1001");
  EXPECT_EQ(row.at("uid"), "1000");
  EXPECT_EQ(row.at("gid"), "1000");
  EXPECT_EQ(row.at("cid"), "12345");
  EXPECT_EQ(row.at("exit_code"), "0");
  EXPECT_EQ(row.at("probe_error"), "0");
  EXPECT_EQ(row.at("parent"), std::to_string(event.parent_process_id));
  EXPECT_EQ(row.at("path"), event.binary_path);
  EXPECT_EQ(row.at("cwd"), event.cwd);
}

TEST_F(BPFProcessEventsTests, generateExecData) {
  auto data =
      BPFProcessEventSubscriber::generateExecData({"cat", "/test folder"});

  EXPECT_EQ(data, "cat '/test folder'");

  data = BPFProcessEventSubscriber::generateExecData({"cat", "file1", "file2"});

  EXPECT_EQ(data, "cat file1 file2");
}

TEST_F(BPFProcessEventsTests, generateExecJsonData) {
  auto data =
      BPFProcessEventSubscriber::generateExecJsonData({"cat", "/test folder"});

  EXPECT_EQ(data, "[\"cat\",\"/test folder\"]");

  data = BPFProcessEventSubscriber::generateExecJsonData(
      {"cat", "file1", "file2"});

  EXPECT_EQ(data, "[\"cat\",\"file1\",\"file2\"]");
}

TEST_F(BPFProcessEventsTests, generateCapCapableData) {
  auto data = BPFProcessEventSubscriber::generateCapCapableData({0});

  EXPECT_EQ(data, "capability=CAP_CHOWN");

  data = BPFProcessEventSubscriber::generateCapCapableData({8});

  EXPECT_EQ(data, "capability=CAP_SETPCAP");

  data = BPFProcessEventSubscriber::generateCapCapableData({1000000});

  EXPECT_EQ(data, "capability=1000000");
}

TEST_F(BPFProcessEventsTests, generateCapCapableJsonData) {
  auto data = BPFProcessEventSubscriber::generateCapCapableJsonData({0});

  EXPECT_EQ(data, "{\"capability\":\"CAP_CHOWN\"}");

  data = BPFProcessEventSubscriber::generateCapCapableJsonData({8});

  EXPECT_EQ(data, "{\"capability\":\"CAP_SETPCAP\"}");

  data = BPFProcessEventSubscriber::generateCapCapableJsonData({1000000});

  EXPECT_EQ(data, "{\"capability\":\"1000000\"}");
}

TEST_F(BPFProcessEventsTests, generatePtraceData) {
  auto data =
      BPFProcessEventSubscriber::generatePtraceData({PTRACE_ATTACH, 1000});

  EXPECT_EQ(data, "request=PTRACE_ATTACH thread_id=1000");

  data = BPFProcessEventSubscriber::generatePtraceData({PTRACE_KILL, 1000});

  EXPECT_EQ(data, "request=PTRACE_KILL thread_id=1000");

  data = BPFProcessEventSubscriber::generatePtraceData({1000000, 1000});

  EXPECT_EQ(data, "request=1000000 thread_id=1000");
}

TEST_F(BPFProcessEventsTests, generatePtraceJsonData) {
  auto data =
      BPFProcessEventSubscriber::generatePtraceJsonData({PTRACE_ATTACH, 1000});

  EXPECT_EQ(data, "{\"request\":\"PTRACE_ATTACH\",\"thread_id\":1000}");

  data = BPFProcessEventSubscriber::generatePtraceJsonData({PTRACE_KILL, 1000});

  EXPECT_EQ(data, "{\"request\":\"PTRACE_KILL\",\"thread_id\":1000}");

  data = BPFProcessEventSubscriber::generatePtraceJsonData({1000000, 1000});

  EXPECT_EQ(data, "{\"request\":\"1000000\",\"thread_id\":1000}");
}

TEST_F(BPFProcessEventsTests, generateInitModuleData) {
  auto data = BPFProcessEventSubscriber::generateInitModuleData(
      {0x1000, 1000, "param=value"});

  EXPECT_EQ(data, "module_image=0x1000 len=1000 param_values=param=value");
}

TEST_F(BPFProcessEventsTests, generateInitModuleJsonData) {
  auto data = BPFProcessEventSubscriber::generateInitModuleJsonData(
      {0x1000, 1000, "param=value"});

  EXPECT_EQ(data,
            "{\"module_image\":\"0x1000\",\"len\":1000,\"param_values\":"
            "\"param=value\"}");
}

TEST_F(BPFProcessEventsTests, generateFinitModuleData) {
  auto data = BPFProcessEventSubscriber::generateFinitModuleData(
      {10, std::nullopt, "param=value", 1000});

  EXPECT_EQ(data, "fd=10 param_values=param=value flags=1000");

  data = BPFProcessEventSubscriber::generateFinitModuleData(
      {10, "/root", "param=value", 1000});

  EXPECT_EQ(data, "fd=10 path=/root param_values=param=value flags=1000");
}

TEST_F(BPFProcessEventsTests, generateFinitModuleJsonData) {
  auto data = BPFProcessEventSubscriber::generateFinitModuleJsonData(
      {10, std::nullopt, "param=value", 1000});

  EXPECT_EQ(data,
            "{\"fd\":10,\"param_values\":\"param=value\",\"flags\":1000}");

  data = BPFProcessEventSubscriber::generateFinitModuleJsonData(
      {10, "/root", "param=value", 1000});

  EXPECT_EQ(data,
            "{\"fd\":10,\"path\":\"/"
            "root\",\"param_values\":\"param=value\",\"flags\":1000}");
}

TEST_F(BPFProcessEventsTests, generateIoctlData) {
  auto data =
      BPFProcessEventSubscriber::generateIoctlData({10, std::nullopt, 1000});

  EXPECT_EQ(data, "fd=10 request=1000");

  data = BPFProcessEventSubscriber::generateIoctlData({10, "/test/path", 1000});

  EXPECT_EQ(data, "fd=10 path=/test/path request=1000");
}

TEST_F(BPFProcessEventsTests, generateIoctlJsonData) {
  auto data = BPFProcessEventSubscriber::generateIoctlJsonData(
      {10, std::nullopt, 1000});

  EXPECT_EQ(data, "{\"fd\":10,\"request\":1000}");

  data = BPFProcessEventSubscriber::generateIoctlJsonData(
      {10, "/test/path", 1000});

  EXPECT_EQ(data, "{\"fd\":10,\"path\":\"/test/path\",\"request\":1000}");
}

TEST_F(BPFProcessEventsTests, generateDeleteModuleData) {
  auto data = BPFProcessEventSubscriber::generateDeleteModuleData(
      {"module_name", 1000});

  EXPECT_EQ(data, "name=module_name flags=1000");
}

TEST_F(BPFProcessEventsTests, generateDeleteModuleJsonData) {
  auto data = BPFProcessEventSubscriber::generateDeleteModuleJsonData(
      {"module_name", 1000});

  EXPECT_EQ(data, "{\"name\":\"module_name\",\"flags\":1000}");
}
} // namespace osquery
