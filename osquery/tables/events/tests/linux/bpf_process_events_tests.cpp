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

namespace osquery {

namespace {

const std::vector<std::string> kExpectedRowList = {"ntime",
                                                   "tid",
                                                   "pid",
                                                   "uid",
                                                   "gid",
                                                   "cid",
                                                   "exit_code",
                                                   "probe_error",
                                                   "syscall",
                                                   "parent",
                                                   "path",
                                                   "cwd",
                                                   "cmdline",
                                                   "json_cmdline"};

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

TEST_F(BPFProcessEventsTests, generateRow) {
  ISystemStateTracker::Event event{};
  event.type = ISystemStateTracker::Event::Type::Exec;
  event.bpf_header = kBaseBPFEventHeader;
  event.parent_process_id = 2;
  event.binary_path = "/usr/bin/sudo";
  event.cwd = "/home/alessandro";

  Row row;
  auto succeeded = BPFProcessEventSubscriber::generateRow(row, event);
  ASSERT_TRUE(succeeded);

  ASSERT_EQ(row.size(), kExpectedRowList.size());
  for (const auto& expected_row : kExpectedRowList) {
    ASSERT_EQ(row.count(expected_row), 1U);
  }

  EXPECT_EQ(row.at("syscall"), "exec");
  EXPECT_EQ(row.at("ntime"), "1234567890");
  EXPECT_EQ(row.at("tid"), "1001");
  EXPECT_EQ(row.at("pid"), "1001");
  EXPECT_EQ(row.at("uid"), "1000");
  EXPECT_EQ(row.at("gid"), "1000");
  EXPECT_EQ(row.at("cid"), "12345");
  EXPECT_EQ(row.at("exit_code"), "0");
  EXPECT_EQ(row.at("probe_error"), "0");
  EXPECT_EQ(row.at("syscall"), "exec");
  EXPECT_EQ(row.at("parent"), std::to_string(event.parent_process_id));
  EXPECT_EQ(row.at("path"), event.binary_path);
  EXPECT_EQ(row.at("cwd"), event.cwd);
  EXPECT_TRUE(row.at("cmdline").empty());
  EXPECT_EQ(row.at("json_cmdline"), "[]");

  ISystemStateTracker::Event::ExecData event_data;
  event_data.argv = {"sudo", "-H", "-i"};
  event.data = std::move(event_data);

  row = {};
  succeeded = BPFProcessEventSubscriber::generateRow(row, event);
  ASSERT_TRUE(succeeded);

  ASSERT_EQ(row.size(), kExpectedRowList.size());
  for (const auto& expected_row : kExpectedRowList) {
    ASSERT_EQ(row.count(expected_row), 1U);
  }

  EXPECT_EQ(row.at("syscall"), "exec");
  EXPECT_EQ(row.at("ntime"), "1234567890");
  EXPECT_EQ(row.at("tid"), "1001");
  EXPECT_EQ(row.at("pid"), "1001");
  EXPECT_EQ(row.at("uid"), "1000");
  EXPECT_EQ(row.at("gid"), "1000");
  EXPECT_EQ(row.at("cid"), "12345");
  EXPECT_EQ(row.at("exit_code"), "0");
  EXPECT_EQ(row.at("probe_error"), "0");
  EXPECT_EQ(row.at("syscall"), "exec");
  EXPECT_EQ(row.at("parent"), std::to_string(event.parent_process_id));
  EXPECT_EQ(row.at("path"), event.binary_path);
  EXPECT_EQ(row.at("cwd"), event.cwd);
  EXPECT_EQ(row.at("cmdline"), "sudo -H -i");
  EXPECT_EQ(row.at("json_cmdline"), "[\"sudo\",\"-H\",\"-i\"]");
}

TEST_F(BPFProcessEventsTests, generateCmdlineColumn) {
  auto cmdline =
      BPFProcessEventSubscriber::generateCmdlineColumn({"cat", "/test folder"});

  EXPECT_EQ(cmdline, "cat '/test folder'");

  cmdline = BPFProcessEventSubscriber::generateCmdlineColumn(
      {"cat", "file1", "file2"});

  EXPECT_EQ(cmdline, "cat file1 file2");
}

} // namespace osquery
