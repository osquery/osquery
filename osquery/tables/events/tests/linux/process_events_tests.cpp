/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <iostream>
#include <map>
#include <set>
#include <string>

#include <gtest/gtest.h>

#include <osquery/events/linux/process_events.h>
#include <osquery/tables/events/linux/process_events.h>

namespace osquery {
namespace {
// clang-format off
const std::vector<std::pair<int, std::string>> kSampleExecveEvent = {
  { 1300, "audit(1502125323.756:6): arch=c000003e syscall=59 success=yes exit=0 a0=23eb8e0 a1=23ebbc0 a2=23c9860 a3=7ffe18d32ed0 items=2 ppid=6882 pid=7841 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=2 comm=\"sh\" exe=\"/usr/bin/bash\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)" },
  { 1309, "audit(1502125323.756:6): argc=1 a0=\"sh\"" },
  { 1307, "audit(1502125323.756:6):  cwd=\"/home/alessandro\"" },
  { 1302, "audit(1502125323.756:6): item=0 name=\"/usr/bin/sh\" inode=18867 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:shell_exec_t:s0 objtype=NORMAL" },
  { 1302, "audit(1502125323.756:6): item=1 name=\"/lib64/ld-linux-x86-64.so.2\" inode=33604032 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:ld_so_t:s0 objtype=NORMAL" },
  { 1320, "audit(1502125323.756:6): " }
};
// clang-format on

// clang-format off
const std::vector<std::pair<int, std::string>> kSampleThreadCloneEvent = {
  { 1300, "audit(1565632189.127:261722): arch=c000003e syscall=56 success=yes exit=33 a0=3d0f00 a1=7f1b92ffcbf0 a2=7f1b92ffd9d0 a3=7f1b92ffd9d0 items=0 ppid=14790 pid=15929 auid=4294967295 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=(none) ses=4294967295 comm=\"ThreadPoolForeg\" exe=\"/usr/lib/chromium-browser/chromium-browser\" key=(null)" },
  { 1327, "audit(1565632189.127:261722): proctitle=2F7573722F6C69622F6368726F6D69756D2D62726F777365722F6368726F6D69756D2D62726F77736572202D2D747970653D72656E6465726572202D2D6669656C642D747269616C2D68616E646C653D31363934333039363539343737363133333433392C31323333383831333239373737313239363539322C313331303732" },
  { 1320, "audit(1565632189.127:261722): " }
};
// clang-format on

bool GenerateAuditEventRecord(AuditEventRecord& event_record,
                              int type,
                              std::string contents) {
  event_record = {};

  audit_reply reply{};
  reply.type = type;
  reply.len = contents.size();
  reply.message = &contents[0];

  return AuditdNetlinkParser::ParseAuditReply(reply, event_record);
}
} // namespace

class ProcessEventsTests : public testing::Test {};

TEST_F(ProcessEventsTests, syscall_name_label) {
  EXPECT_EQ(
      kExecProcessEventsSyscalls.size() + kForkProcessEventsSyscalls.size(),
      AuditProcessEventSubscriber::GetSyscallNameMap().size());

  std::string name;

  for (auto syscall_nr : kExecProcessEventsSyscalls) {
    auto status = AuditProcessEventSubscriber::GetSyscallName(name, syscall_nr);
    EXPECT_TRUE(status);
  }

  for (auto syscall_nr : kForkProcessEventsSyscalls) {
    auto status = AuditProcessEventSubscriber::GetSyscallName(name, syscall_nr);
    EXPECT_TRUE(status);
  }
}

TEST_F(ProcessEventsTests, exec_event_processing) {
  std::vector<AuditEventRecord> event_list;

  for (const auto& record_descriptor : kSampleExecveEvent) {
    std::string audit_message_copy = record_descriptor.second;

    audit_reply reply = {};
    reply.type = record_descriptor.first;
    reply.len = audit_message_copy.size();
    reply.message = &audit_message_copy[0];

    AuditEventRecord audit_event_record = {};

    bool parser_status =
        AuditdNetlinkParser::ParseAuditReply(reply, audit_event_record);

    EXPECT_TRUE(parser_status);

    event_list.push_back(audit_event_record);
  }

  EXPECT_EQ(event_list.size(), kSampleExecveEvent.size());

  // Assemble the audit records into audit events, and make sure
  // we get the correct amount of objects
  auto event_context = std::make_shared<AuditEventContext>();
  AuditTraceContext audit_trace_context;

  AuditEventPublisher::ProcessEvents(
      event_context, event_list, audit_trace_context);

  EXPECT_EQ(audit_trace_context.size(), 0U);
  EXPECT_EQ(event_context->audit_events.size(), 1U);

  std::vector<Row> row_list;
  auto status = AuditProcessEventSubscriber::ProcessEvents(
      row_list, event_context->audit_events);
  EXPECT_TRUE(status.ok());

  EXPECT_EQ(row_list.size(), 1U);

  const auto& event_row = row_list.at(0U);

  const std::vector<std::string> kExpectedFields = {"uptime",
                                                    "ctime",
                                                    "atime",
                                                    "mtime",
                                                    "overflows",
                                                    "env",
                                                    "env_size",
                                                    "env_count",
                                                    "btime"};

  const std::unordered_map<std::string, std::string> kExpectedFieldMap = {
      {"auid", "1000"},
      {"pid", "7841"},
      {"uid", "1000"},
      {"euid", "1000"},
      {"gid", "1000"},
      {"egid", "1000"},
      {"syscall", "execve"},
      {"parent", "6882"},
      {"path", "/usr/bin/bash"},
      {"cwd", "\"/home/alessandro\""},
      {"cmdline", "sh"},
      {"cmdline_size", "2"},
      {"mode", "0100755"},
      {"owner_uid", "0"},
      {"owner_gid", "0"}};

  for (const auto& key : kExpectedFields) {
    EXPECT_TRUE(event_row.find(key) != event_row.end());
  }

  for (const auto& p : kExpectedFieldMap) {
    const auto& key = p.first;
    const auto& expected_value = p.second;

    auto it = event_row.find(key);
    EXPECT_TRUE(it != event_row.end());

    if (it == event_row.end()) {
      std::cout << key << " WAS NOT FOUND" << std::endl;
      continue;
    }

    const auto& actual_value = it->second;
    EXPECT_EQ(expected_value, actual_value);
  }
}

TEST_F(ProcessEventsTests, thread_detection) {
  const std::string kThreadCreationSyscallRecord =
      "audit(1565632189.127:261722): arch=c000003e syscall=56 success=yes "
      "exit=33 a0=3d0f00 "
      "a1=7f1b92ffcbf0 a2=7f1b92ffd9d0 a3=7f1b92ffd9d0 items=0 ppid=14790 "
      "pid=15929 "
      "auid=4294967295 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
      "egid=1000 sgid=1000 "
      "fsgid=1000 tty=(none) ses=4294967295 comm=\"ThreadPoolForeg\" "
      "exe=\"/usr/lib/chromium-browser/chromium-browser\" key=(null)";

  AuditEventRecord event_record{};

  {
    auto status = GenerateAuditEventRecord(
        event_record, AUDIT_SYSCALL, kThreadCreationSyscallRecord);
    EXPECT_TRUE(status);

    if (!status) {
      return;
    }
  }

  // Process a valid thread creation event
  bool is_thread{false};
  auto status = AuditProcessEventSubscriber::IsThreadClone(
      is_thread, __NR_clone, event_record);

  EXPECT_TRUE(status.ok());
  EXPECT_TRUE(is_thread);

  // Pass another record, this time with the wrong syscall number
  status = AuditProcessEventSubscriber::IsThreadClone(
      is_thread, __NR_execve, event_record);

  EXPECT_TRUE(status.ok());
  EXPECT_FALSE(is_thread);

  // Pass the wrong record type
  event_record.type = AUDIT_PATH;
  status = AuditProcessEventSubscriber::IsThreadClone(
      is_thread, __NR_clone, event_record);

  EXPECT_FALSE(status.ok());
  EXPECT_FALSE(is_thread);
}
} // namespace osquery
