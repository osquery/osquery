/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include "osquery/events/linux/auditeventpublisher.h"
#include "osquery/tables/events/linux/seccomp_events.h"

namespace osquery {
class SeccompEventsTests : public testing::Test {
 protected:
  SeccompAuditEventData event_data;
  AuditEvent audit_event;
  AuditEventRecord fake_record;
  std::vector<AuditEvent> event_list;
  QueryData data;

  void ProcessEventsWithParams(std::uint64_t syscall_num,
                               std::uint64_t arch,
                               std::uint64_t seccomp_action,
                               Row& result) {
    event_data.fields["syscall"] = syscall_num;
    event_data.fields["arch"] = arch;
    event_data.fields["code"] = seccomp_action;

    audit_event.data = event_data;
    event_list.push_back(audit_event);

    data.clear();
    SeccompEventSubscriber::processEvents(data, event_list);
    result = data.back();
    event_list.clear();
  }

  void SetUp() override {
    event_data.fields["auid"] = 65876;
    event_data.fields["uid"] = 0;
    event_data.fields["gid"] = 0;
    event_data.fields["ses"] = 162176;
    event_data.fields["pid"] = 14970;
    event_data.fields["comm"] = "qemu-system-x86";
    event_data.fields["exe"] = "/usr/bin/qemu-system-x86_64";
    event_data.fields["sig"] = 0;
    event_data.fields["arch"] = AUDIT_ARCH_IA64;
    event_data.fields["syscall"] = 1;
    event_data.fields["compat"] = 0;
    event_data.fields["ip"] = 0x7fe6aa0bf51d;
    event_data.fields["code"] = SECCOMP_RET_ALLOW;

    audit_event.type = AuditEvent::Type::Seccomp;
    audit_event.record_list.push_back(fake_record);
  }
};

TEST_F(SeccompEventsTests, test_basic_fields) {
  Row result;
  ProcessEventsWithParams(0, AUDIT_ARCH_IA64, SECCOMP_RET_ALLOW, result);

  EXPECT_EQ(result["auid"], "65876");
  EXPECT_EQ(result["uid"], "0");
  EXPECT_EQ(result["gid"], "0");
  EXPECT_EQ(result["ses"], "162176");
  EXPECT_EQ(result["pid"], "14970");
  EXPECT_EQ(result["comm"], "qemu-system-x86");
  EXPECT_EQ(result["exe"], "/usr/bin/qemu-system-x86_64");
  EXPECT_EQ(result["sig"], "0");
  EXPECT_EQ(result["compat"], "0");
  EXPECT_EQ(result["ip"], "140628672115997");
}

TEST_F(SeccompEventsTests, test_seccomp_value_decode_x86_64_1) {
  Row result;
  ProcessEventsWithParams(0, AUDIT_ARCH_X86_64, SECCOMP_RET_LOG, result);

  EXPECT_EQ(result["syscall"], "read");
  EXPECT_EQ(result["arch"], "X86_64");
  EXPECT_EQ(result["code"], "LOG");
}

TEST_F(SeccompEventsTests, test_seccomp_value_decode_x86_64_2) {
  Row result;
  ProcessEventsWithParams(
      88, AUDIT_ARCH_X86_64, SECCOMP_RET_KILL_PROCESS, result);

  EXPECT_EQ(result["syscall"], "symlink");
  EXPECT_EQ(result["arch"], "X86_64");
  EXPECT_EQ(result["code"], "KILL_PROCESS");
}

TEST_F(SeccompEventsTests, test_seccomp_value_decode_x86_64_3) {
  Row result;
  ProcessEventsWithParams(
      1337, AUDIT_ARCH_X86_64, SECCOMP_RET_KILL_THREAD, result);

  EXPECT_EQ(result["syscall"], "1337(unknown)");
  EXPECT_EQ(result["arch"], "X86_64");
  EXPECT_EQ(result["code"], "KILL_THREAD");
}

TEST_F(SeccompEventsTests, test_seccomp_value_decode_mips) {
  Row result;
  ProcessEventsWithParams(13, AUDIT_ARCH_MIPS64, SECCOMP_RET_ERRNO, result);

  EXPECT_EQ(result["syscall"], "13");
  EXPECT_EQ(result["arch"], "MIPS64");
  EXPECT_EQ(result["code"], "ERRNO");
}
} // namespace osquery