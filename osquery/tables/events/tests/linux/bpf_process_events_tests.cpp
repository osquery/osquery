/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/events/linux/bpf/bpf_process_event_publisher.h>
#include <osquery/tables/events/linux/bpf_process_events.h>

namespace osquery {

class BPFProcessEventsTests : public testing::Test {};

TEST_F(BPFProcessEventsTests, test_event_row_generation) {
  BPFProcessEvent event = {};
  event.timestamp = 123456789;
  event.pid = 100;
  event.tid = 101;
  event.ppid = 1;
  event.uid = 1000;
  event.gid = 1000;
  event.cgroup_id = 42;
  event.exit_code = 0;
  event.duration = 5000;
  event.probe_error = 0;
  event.comm = "test_cmd";
  event.path = "/bin/test_cmd";
  event.cwd = "/home/user";
  event.args = "arg1 arg2";

  Row row;
  bool status = BPFProcessEventSubscriber::generateRow(row, event);
  ASSERT_TRUE(status);

  EXPECT_EQ(row["tid"], "101");
  EXPECT_EQ(row["pid"], "100");
  EXPECT_EQ(row["parent"], "1");
  EXPECT_EQ(row["uid"], "1000");
  EXPECT_EQ(row["gid"], "1000");
  EXPECT_EQ(row["cid"], "42");
  EXPECT_EQ(row["exit_code"], "0");
  EXPECT_EQ(row["probe_error"], "0");
  EXPECT_EQ(row["syscall"], "execve");
  EXPECT_EQ(row["path"], "/bin/test_cmd");
  EXPECT_EQ(row["cwd"], "/home/user");
  EXPECT_EQ(row["cmdline"], "arg1 arg2");
  EXPECT_EQ(row["duration"], "5000");
  EXPECT_EQ(row["ntime"], "123456789");
  EXPECT_EQ(row["json_cmdline"], "[\"arg1\",\"arg2\"]");
}

TEST_F(BPFProcessEventsTests, test_failed_event) {
  BPFProcessEvent event = {};
  event.exit_code = -1; // Failed syscall

  Row row;
  bool status = BPFProcessEventSubscriber::generateRow(row, event);
  ASSERT_FALSE(status);
}

TEST_F(BPFProcessEventsTests, test_json_cmdline_complex) {
  BPFProcessEvent event = {};
  event.timestamp = 1;
  event.pid = 1;
  event.args = "ls -la /home/user";

  Row row;
  bool status = BPFProcessEventSubscriber::generateRow(row, event);
  ASSERT_TRUE(status);

  EXPECT_EQ(row["cmdline"], "ls -la /home/user");
  EXPECT_EQ(row["json_cmdline"], "[\"ls\",\"-la\",\"/home/user\"]");
}

} // namespace osquery
