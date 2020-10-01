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
const std::vector<std::string> kExpectedRowList = {"bpf_time",
                                                   "thread_id",
                                                   "process_id",
                                                   "uid",
                                                   "gid",
                                                   "cgroup_id",
                                                   "exit_code",
                                                   "probe_error",
                                                   "syscall",
                                                   "parent_process_id",
                                                   "binary_path",
                                                   "cwd",
                                                   "cmdline"};

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
  EXPECT_EQ(row.at("bpf_time"), "1234567890");
  EXPECT_EQ(row.at("thread_id"), "1001");
  EXPECT_EQ(row.at("process_id"), "1001");
  EXPECT_EQ(row.at("uid"), "1000");
  EXPECT_EQ(row.at("gid"), "1000");
  EXPECT_EQ(row.at("cgroup_id"), "12345");
  EXPECT_EQ(row.at("exit_code"), "0");
  EXPECT_EQ(row.at("probe_error"), "0");
  EXPECT_EQ(row.at("syscall"), "exec");
  EXPECT_EQ(row.at("parent_process_id"),
            std::to_string(event.parent_process_id));

  EXPECT_EQ(row.at("binary_path"), event.binary_path);
  EXPECT_EQ(row.at("cwd"), event.cwd);
  EXPECT_TRUE(row.at("cmdline").empty());

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
  EXPECT_EQ(row.at("bpf_time"), "1234567890");
  EXPECT_EQ(row.at("thread_id"), "1001");
  EXPECT_EQ(row.at("process_id"), "1001");
  EXPECT_EQ(row.at("uid"), "1000");
  EXPECT_EQ(row.at("gid"), "1000");
  EXPECT_EQ(row.at("cgroup_id"), "12345");
  EXPECT_EQ(row.at("exit_code"), "0");
  EXPECT_EQ(row.at("probe_error"), "0");
  EXPECT_EQ(row.at("syscall"), "exec");
  EXPECT_EQ(row.at("parent_process_id"),
            std::to_string(event.parent_process_id));

  EXPECT_EQ(row.at("binary_path"), event.binary_path);
  EXPECT_EQ(row.at("cwd"), event.cwd);
  EXPECT_EQ(row.at("cmdline"), "\"sudo\" \"-H\" \"-i\"");
}
} // namespace osquery
