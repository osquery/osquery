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
using RawAuditEvent = const std::vector<std::pair<int, std::string>>;

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

bool GenerateAuditEvent(std::vector<AuditEventRecord>& record_list,
                        const RawAuditEvent& audit_event) {
  record_list.clear();
  record_list.reserve(audit_event.size());

  for (const auto& record_descriptor : audit_event) {
    const auto& record_type = record_descriptor.first;
    const auto& record_data = record_descriptor.second;

    AuditEventRecord event_record = {};
    auto status =
        GenerateAuditEventRecord(event_record, record_type, record_data);

    EXPECT_TRUE(status);
    if (!status) {
      return false;
    }

    record_list.push_back(std::move(event_record));
  }

  return true;
}

bool GenerateEventContext(std::shared_ptr<AuditEventContext>& event_context,
                          const RawAuditEvent& audit_event) {
  event_context.reset();

  std::vector<AuditEventRecord> record_list;
  auto status = GenerateAuditEvent(record_list, audit_event);

  EXPECT_TRUE(status);
  if (!status) {
    return false;
  }

  EXPECT_EQ(record_list.size(), audit_event.size());
  if (record_list.size() != audit_event.size()) {
    return false;
  }

  event_context = std::make_shared<AuditEventContext>();
  AuditTraceContext audit_trace_context;

  AuditEventPublisher::ProcessEvents(
      event_context, record_list, audit_trace_context);

  EXPECT_EQ(audit_trace_context.size(), 0U);
  if (audit_trace_context.size() != 0U) {
    return false;
  }

  EXPECT_EQ(event_context->audit_events.size(), 1U);
  if (event_context->audit_events.size() != 1U) {
    return false;
  }

  return true;
}

bool GenerateEventRow(Row& row, const RawAuditEvent& audit_event) {
  row.clear();

  std::shared_ptr<AuditEventContext> event_context;

  {
    auto status = GenerateEventContext(event_context, audit_event);

    EXPECT_TRUE(status);
    if (!status) {
      return false;
    }
  }

  std::vector<Row> row_list;
  auto status = AuditProcessEventSubscriber::ProcessEvents(
      row_list, event_context->audit_events);

  EXPECT_TRUE(status.ok());
  if (!status.ok()) {
    return false;
  }

  EXPECT_EQ(row_list.size(), 1U);
  if (row_list.size() != 1U) {
    return false;
  }

  row = row_list.at(0U);
  return true;
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
  // clang-format off
  const RawAuditEvent kSampleExecveEvent = {
    { 1300, "audit(1502125323.756:6): arch=c000003e syscall=59 success=yes exit=0 a0=23eb8e0 a1=23ebbc0 a2=23c9860 a3=7ffe18d32ed0 items=2 ppid=6882 pid=7841 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=2 comm=\"sh\" exe=\"/usr/bin/bash\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)" },
    { 1309, "audit(1502125323.756:6): argc=1 a0=\"sh\"" },
    { 1307, "audit(1502125323.756:6):  cwd=\"/home/alessandro\"" },
    { 1302, "audit(1502125323.756:6): item=0 name=\"/usr/bin/sh\" inode=18867 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:shell_exec_t:s0 objtype=NORMAL" },
    { 1302, "audit(1502125323.756:6): item=1 name=\"/lib64/ld-linux-x86-64.so.2\" inode=33604032 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:ld_so_t:s0 objtype=NORMAL" },
    { 1320, "audit(1502125323.756:6): " }
  };
  // clang-format on

  Row event_row;
  auto status = GenerateEventRow(event_row, kSampleExecveEvent);

  EXPECT_TRUE(status);
  if (!status) {
    return;
  }

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
      "exit=33 a0=3d0f00 a1=7f1b92ffcbf0 a2=7f1b92ffd9d0 a3=7f1b92ffd9d0 "
      "items=0 ppid=14790 pid=15929 auid=4294967295 uid=1000 gid=1000 "
      "euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 "
      "tty=(none) ses=4294967295 comm=\"ThreadPoolForeg\" "
      "exe=\"/usr/lib/chromium-browser/chromium-browser\" key=(null)";

  const std::string kProcessCreationSyscallRecord =
      "audit(1565632189.127:261722): arch=c000003e syscall=56 success=yes "
      "exit=33 a0=1200000 a1=7f1b92ffcbf0 a2=7f1b92ffd9d0 a3=7f1b92ffd9d0 "
      "items=0 ppid=14790 pid=15929 auid=4294967295 uid=1000 gid=1000 "
      "euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 "
      "tty=(none) ses=4294967295 comm=\"ThreadPoolForeg\" "
      "exe=\"/usr/lib/chromium-browser/chromium-browser\" key=(null)";

  // Thread creation event
  AuditEventRecord event_record{};

  {
    auto status = GenerateAuditEventRecord(
        event_record, AUDIT_SYSCALL, kThreadCreationSyscallRecord);

    EXPECT_TRUE(status);
    if (!status) {
      return;
    }
  }

  bool is_thread{false};
  auto status = AuditProcessEventSubscriber::IsThreadClone(
      is_thread, __NR_clone, event_record);

  EXPECT_TRUE(status.ok());
  EXPECT_TRUE(is_thread);

  // Process creation event
  event_record = {};

  {
    auto status = GenerateAuditEventRecord(
        event_record, AUDIT_SYSCALL, kProcessCreationSyscallRecord);

    EXPECT_TRUE(status);
    if (!status) {
      return;
    }
  }

  status = AuditProcessEventSubscriber::IsThreadClone(
      is_thread, __NR_clone, event_record);

  EXPECT_TRUE(status.ok());
  EXPECT_FALSE(is_thread);

  // Other syscalls should be ignored
  status = AuditProcessEventSubscriber::IsThreadClone(
      is_thread, __NR_execve, event_record);

  EXPECT_TRUE(status.ok());
  EXPECT_FALSE(is_thread);

  // The wrong record type should trigger an error
  event_record.type = AUDIT_PATH;
  status = AuditProcessEventSubscriber::IsThreadClone(
      is_thread, __NR_clone, event_record);

  EXPECT_FALSE(status.ok());
  EXPECT_FALSE(is_thread);
}
} // namespace osquery
