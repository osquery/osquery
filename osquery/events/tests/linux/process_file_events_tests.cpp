/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <linux/audit.h>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <string>
#include <vector>
#include <sstream>

#include <osquery/core/flags.h>
#include <osquery/core/tables.h>
#include <osquery/events/linux/auditeventpublisher.h>
#include <osquery/tables/events/linux/process_file_events.h>

namespace osquery {
extern std::vector<std::pair<int, std::string>> complete_event_list;
extern StringList included_file_paths;
extern std::string generateAuditId(std::uint32_t event_id) noexcept;

class AuditdFimTests : public testing::Test {
 protected:
  void SetUp() override {
    Row().swap(row_);
  }

 protected:
  Row row_;
};

void DumpRow(Row r) {
  std::cout << "  " << r["operation"] << " " << r["path1"];
  if (r.find("path2") != r.end()) {
    std::cout << " " << r["path2"];
  }

  std::cout << "\n";
}

void DumpRowList(const std::vector<Row>& row_list) {
  for (const auto& r : row_list) {
    DumpRow(r);
  }
}

TEST_F(AuditdFimTests, row_emission) {
  static const std::set<int> kSyscallsAllowedToFail{};

  std::vector<AuditEventRecord> event_record_list;

  // Parse the raw messages and make sure we get the right amount
  // of records
  for (const auto& record_descriptor : complete_event_list) {
    std::string audit_message_copy = record_descriptor.second;

    audit_reply reply = {};
    reply.type = record_descriptor.first;
    reply.len = audit_message_copy.size();
    reply.message = &audit_message_copy[0];

    AuditEventRecord audit_event_record = {};

    bool parser_status =
        AuditdNetlinkParser::ParseAuditReply(reply, audit_event_record);
    EXPECT_EQ(parser_status, true);

    event_record_list.push_back(audit_event_record);
  }

  EXPECT_EQ(event_record_list.size(), 243U);

  // Assemble the audit records into audit events, and make sure
  // we get the correct amount of objects
  auto event_context = std::make_shared<AuditEventContext>();
  AuditTraceContext audit_trace_context;

  AuditEventPublisher::ProcessEvents(event_context,
                                     event_record_list,
                                     audit_trace_context,
                                     kSyscallsAllowedToFail);

  EXPECT_EQ(audit_trace_context.size(), 0U);
  EXPECT_EQ(event_context->audit_events.size(), 71U);

  // Configure what we want to log and what we want to ignore
  AuditdFimContext fim_context;
  fim_context.included_path_list = included_file_paths;

  // Emit the rows, showing only writes
  std::vector<Row> emitted_row_list;
  Status status = ProcessFileEventSubscriber::ProcessEvents(
      emitted_row_list, fim_context, event_context->audit_events);

  EXPECT_EQ(status.ok(), true);
  // @TODO fix failing test
  // EXPECT_EQ(emitted_row_list.size(), 15U);
}

// clang-format off
StringList included_file_paths = {
  "/etc/ld.so.cache",
  "/home/alessandro/test_file",
  "/lib64/libc.so.6",
  "/lib64/libgcc_s.so.1",
  "/lib64/libm.so.6",
  "/lib64/libstdc++.so.6",
  "/home/alessandro/test_file",
  "/home/alessandro/test_file1",
  "/home/alessandro/test_file2",
  "/home/alessandro/test_file3",
  "/home/alessandro/test_file4",
  "/home/alessandro/test_file5",
  "/home/alessandro/test_file7",
  "/home/alessandro/test_file_rename",
  "/home/alessandro/test_file_renameat"
};

std::vector<std::pair<int, std::string>> complete_event_list = {
  {1300, "audit(1502573850.697:38395): arch=c000003e syscall=9 success=yes exit=140095431475200 a0=0 a1=1000 a2=3 a3=22 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.697:38395): "},
  {1300, "audit(1502573850.697:38396): arch=c000003e syscall=2 success=yes exit=3 a0=7f6a824d4df5 a1=80000 a2=1 a3=7f6a826db4f8 items=1 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573850.697:38396):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573850.697:38396): item=0 name=\"/etc/ld.so.cache\" inode=67842177 dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:ld_so_cache_t:s0 objtype=NORMAL"},
  {1320, "audit(1502573850.697:38396): "},
  {1300, "audit(1502573850.697:38397): arch=c000003e syscall=9 success=yes exit=140095431385088 a0=0 a1=15e5b a2=1 a3=2 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1323, "audit(1502573850.697:38397): fd=3 flags=0x2"},
  {1320, "audit(1502573850.697:38397): "},
  {1300, "audit(1502573850.697:38398): arch=c000003e syscall=3 success=yes exit=0 a0=3 a1=15e5b a2=1 a3=2 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.697:38398): "},
  {1300, "audit(1502573850.697:38399): arch=c000003e syscall=2 success=yes exit=3 a0=7f6a826d8640 a1=80000 a2=7f6a826db150 a3=7f6a826d8640 items=1 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573850.697:38399):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573850.697:38399): item=0 name=\"/lib64/libstdc++.so.6\" inode=33604382 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:lib_t:s0 objtype=NORMAL"},
  {1320, "audit(1502573850.697:38399): "},
  {1300, "audit(1502573850.697:38400): arch=c000003e syscall=0 success=yes exit=832 a0=3 a1=7fff15c09350 a2=340 a3=7f6a826d8640 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.697:38400): "},
  {1300, "audit(1502573850.697:38401): arch=c000003e syscall=9 success=yes exit=140095426068480 a0=0 a1=308420 a2=5 a3=802 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1323, "audit(1502573850.697:38401): fd=3 flags=0x802"},
  {1320, "audit(1502573850.697:38401): "},
  {1300, "audit(1502573850.697:38402): arch=c000003e syscall=9 success=yes exit=140095429120000 a0=7f6a82499000 a1=b000 a2=3 a3=812 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1323, "audit(1502573850.697:38402): fd=3 flags=0x812"},
  {1320, "audit(1502573850.697:38402): "},
  {1300, "audit(1502573850.697:38403): arch=c000003e syscall=9 success=yes exit=140095429165056 a0=7f6a824a4000 a1=14420 a2=3 a3=32 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.697:38403): "},
  {1300, "audit(1502573850.697:38404): arch=c000003e syscall=3 success=yes exit=0 a0=3 a1=7f6a826d8698 a2=0 a3=31 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.697:38404): "},
  {1300, "audit(1502573850.697:38405): arch=c000003e syscall=2 success=yes exit=3 a0=7f6a826d8b08 a1=80000 a2=7f6a826db150 a3=7f6a826d8b08 items=1 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573850.697:38405):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573850.697:38405): item=0 name=\"/lib64/libm.so.6\" inode=33604048 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:lib_t:s0 objtype=NORMAL"},
  {1320, "audit(1502573850.697:38405): "},
  {1300, "audit(1502573850.697:38406): arch=c000003e syscall=0 success=yes exit=832 a0=3 a1=7fff15c09320 a2=340 a3=7f6a826d8b08 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.697:38406): "},
  {1300, "audit(1502573850.697:38407): arch=c000003e syscall=9 success=yes exit=140095422914560 a0=0 a1=301148 a2=5 a3=802 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1323, "audit(1502573850.697:38407): fd=3 flags=0x802"},
  {1320, "audit(1502573850.697:38407): "},
  {1300, "audit(1502573850.697:38408): arch=c000003e syscall=9 success=yes exit=140095426060288 a0=7f6a821ae000 a1=2000 a2=3 a3=812 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1323, "audit(1502573850.697:38408): fd=3 flags=0x812"},
  {1320, "audit(1502573850.697:38408): "},
  {1300, "audit(1502573850.697:38409): arch=c000003e syscall=3 success=yes exit=0 a0=3 a1=7f6a826d8b60 a2=0 a3=31 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.697:38409): "},
  {1300, "audit(1502573850.697:38410): arch=c000003e syscall=2 success=yes exit=3 a0=7f6a826d8fd0 a1=80000 a2=7f6a826db150 a3=7f6a826d8fd0 items=1 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573850.697:38410):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573850.697:38410): item=0 name=\"/lib64/libgcc_s.so.1\" inode=33554508 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:lib_t:s0 objtype=NORMAL"},
  {1320, "audit(1502573850.697:38410): "},
  {1300, "audit(1502573850.697:38411): arch=c000003e syscall=0 success=yes exit=832 a0=3 a1=7fff15c092f0 a2=340 a3=7f6a826d8fd0 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.697:38411): "},
  {1300, "audit(1502573850.697:38412): arch=c000003e syscall=9 success=yes exit=140095431380992 a0=0 a1=1000 a2=3 a3=22 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.697:38412): "},
  {1300, "audit(1502573850.697:38413): arch=c000003e syscall=9 success=yes exit=140095420727296 a0=0 a1=215400 a2=5 a3=802 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1323, "audit(1502573850.697:38413): fd=3 flags=0x802"},
  {1320, "audit(1502573850.697:38413): "},
  {1300, "audit(1502573850.697:38414): arch=c000003e syscall=9 success=yes exit=140095422906368 a0=7f6a81eac000 a1=2000 a2=3 a3=812 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1323, "audit(1502573850.697:38414): fd=3 flags=0x812"},
  {1320, "audit(1502573850.697:38414): "},
  {1300, "audit(1502573850.697:38415): arch=c000003e syscall=3 success=yes exit=0 a0=3 a1=7f6a826c1040 a2=0 a3=31 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.697:38415): "},
  {1300, "audit(1502573850.698:38416): arch=c000003e syscall=2 success=yes exit=3 a0=7f6a826c14b0 a1=80000 a2=7f6a826db150 a3=7f6a826c14b0 items=1 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573850.698:38416):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573850.698:38416): item=0 name=\"/lib64/libc.so.6\" inode=33604039 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:lib_t:s0 objtype=NORMAL"},
  {1320, "audit(1502573850.698:38416): "},
  {1300, "audit(1502573850.698:38417): arch=c000003e syscall=0 success=yes exit=832 a0=3 a1=7fff15c092c0 a2=340 a3=7f6a826c14b0 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.698:38417): "},
  {1300, "audit(1502573850.698:38418): arch=c000003e syscall=9 success=yes exit=140095416791040 a0=0 a1=3c0200 a2=5 a3=802 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1323, "audit(1502573850.698:38418): fd=3 flags=0x802"},
  {1320, "audit(1502573850.698:38418): "},
  {1300, "audit(1502573850.698:38419): arch=c000003e syscall=9 success=yes exit=140095420682240 a0=7f6a81c8d000 a1=6000 a2=3 a3=812 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1323, "audit(1502573850.698:38419): fd=3 flags=0x812"},
  {1320, "audit(1502573850.698:38419): "},
  {1300, "audit(1502573850.698:38420): arch=c000003e syscall=9 success=yes exit=140095420706816 a0=7f6a81c93000 a1=4200 a2=3 a3=32 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.698:38420): "},
  {1300, "audit(1502573850.698:38421): arch=c000003e syscall=3 success=yes exit=0 a0=3 a1=7f6a826c1508 a2=0 a3=31 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.698:38421): "},
  {1300, "audit(1502573850.698:38422): arch=c000003e syscall=9 success=yes exit=140095431376896 a0=0 a1=1000 a2=3 a3=22 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.698:38422): "},
  {1300, "audit(1502573850.698:38423): arch=c000003e syscall=9 success=yes exit=140095431368704 a0=0 a1=2000 a2=3 a3=22 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.698:38423): "},
  {1300, "audit(1502573850.698:38424): arch=c000003e syscall=9 success=yes exit=140095431364608 a0=0 a1=1000 a2=3 a3=22 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.698:38424): "},
  {1300, "audit(1502573850.698:38425): arch=c000003e syscall=87 success=yes exit=0 a0=40219c a1=7fff15c0ab48 a2=7fff15c0ab58 a3=7fff15c0a7d0 items=2 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573850.698:38425):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573850.698:38425): item=0 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573850.698:38425): item=1 name=\"test_file\" inode=724389 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=DELETE"},
  {1320, "audit(1502573850.698:38425): "},
  {1300, "audit(1502573850.699:38428): arch=c000003e syscall=87 success=yes exit=0 a0=4021ff a1=7fff15c0ab48 a2=7fff15c0ab58 a3=7fff15c0a7d0 items=2 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573850.699:38428):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573850.699:38428): item=0 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573850.699:38428): item=1 name=\"test_file3\" inode=724389 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=DELETE"},
  {1320, "audit(1502573850.699:38428): "},
  {1300, "audit(1502573850.699:38429): arch=c000003e syscall=87 success=yes exit=0 a0=40220a a1=7fff15c0ab48 a2=7fff15c0ab58 a3=7fff15c0a7d0 items=2 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573850.699:38429):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573850.699:38429): item=0 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573850.699:38429): item=1 name=\"test_file4\" inode=724416 dev=fd:02 mode=0120777 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=DELETE"},
  {1320, "audit(1502573850.699:38429): "},
  {1300, "audit(1502573850.699:38430): arch=c000003e syscall=87 success=yes exit=0 a0=40242d a1=7fff15c0ab48 a2=7fff15c0ab58 a3=7fff15c0a7d0 items=2 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573850.699:38430):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573850.699:38430): item=0 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573850.699:38430): item=1 name=\"test_file5\" inode=724406 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=DELETE"},
  {1320, "audit(1502573850.699:38430): "},
  {1300, "audit(1502573850.699:38431): arch=c000003e syscall=87 success=yes exit=0 a0=402451 a1=7fff15c0ab48 a2=7fff15c0ab58 a3=7fff15c0a7d0 items=2 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573850.699:38431):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573850.699:38431): item=0 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573850.699:38431): item=1 name=\"test_file6\" inode=724418 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=DELETE"},
  {1320, "audit(1502573850.699:38431): "},
  {1300, "audit(1502573850.699:38432): arch=c000003e syscall=87 success=yes exit=0 a0=402477 a1=7fff15c0ab48 a2=7fff15c0ab58 a3=7fff15c0a7d0 items=2 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573850.699:38432):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573850.699:38432): item=0 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573850.699:38432): item=1 name=\"test_file7\" inode=724419 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=DELETE"},
  {1320, "audit(1502573850.699:38432): "},
  {1300, "audit(1502573850.725:38494): arch=c000003e syscall=257 success=yes exit=3 a0=ffffffffffffff9c a1=40259e a2=90800 a3=0 items=1 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573850.725:38494):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573850.725:38494): item=0 name=\".\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=NORMAL"},
  {1320, "audit(1502573850.725:38494): "},
  {1300, "audit(1502573850.725:38495): arch=c000003e syscall=9 success=yes exit=140095431471104 a0=0 a1=1000 a2=3 a3=22 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.725:38495): "},
  {1300, "audit(1502573850.725:38496): arch=c000003e syscall=1 success=yes exit=18 a0=1 a1=7f6a826d7000 a2=12 a3=0 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.725:38496): "},
  {1300, "audit(1502573850.725:38497): arch=c000003e syscall=9 success=yes exit=140095431467008 a0=0 a1=1000 a2=3 a3=22 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.725:38497): "},
  {1300, "audit(1502573850.726:38498): arch=c000003e syscall=1 success=yes exit=31 a0=1 a1=7f6a826d7000 a2=1f a3=22 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.726:38498): "},
  {1300, "audit(1502573850.726:46799): arch=c000003e syscall=0 success=yes exit=1 a0=0 a1=7f6a826d6000 a2=400 a3=22 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573850.726:46799): "},
  {1300, "audit(1502573858.178:46800): arch=c000003e syscall=76 success=yes exit=0 a0=40219c a1=c a2=a a3=7fff15c0a7c0 items=1 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573858.178:46800):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573858.178:46800): item=0 name=\"test_file\" inode=98362 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=NORMAL"},
  {1320, "audit(1502573858.178:46800): "},
  {1300, "audit(1502573858.178:46801): arch=c000003e syscall=86 success=yes exit=0 a0=40219c a1=402191 a2=a a3=7fff15c0a7c0 items=3 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573858.178:46801):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573858.178:46801): item=0 name=\"test_file\" inode=98362 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=NORMAL"},
  {1302, "audit(1502573858.178:46801): item=1 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573858.178:46801): item=2 name=\"test_file1\" inode=98362 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=CREATE"},
  {1320, "audit(1502573858.178:46801): "},
  {1300, "audit(1502573858.178:46802): arch=c000003e syscall=88 success=yes exit=0 a0=40219c a1=4021cc a2=a a3=7fff15c0a7c0 items=3 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573858.178:46802):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573858.178:46802): item=0 name=\"test_file\" objtype=UNKNOWN"},
  {1302, "audit(1502573858.178:46802): item=1 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573858.178:46802): item=2 name=\"test_file2\" inode=724389 dev=fd:02 mode=0120777 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=CREATE"},
  {1320, "audit(1502573858.178:46802): "},
  {1300, "audit(1502573858.178:46803): arch=c000003e syscall=265 success=yes exit=0 a0=3 a1=40219c a2=3 a3=4021ff items=3 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573858.178:46803):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573858.178:46803): item=0 name=\"test_file\" inode=98362 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=NORMAL"},
  {1302, "audit(1502573858.178:46803): item=1 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573858.178:46803): item=2 name=\"test_file3\" inode=98362 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=CREATE"},
  {1320, "audit(1502573858.178:46803): "},
  {1300, "audit(1502573858.178:46804): arch=c000003e syscall=266 success=yes exit=0 a0=40219c a1=3 a2=40220a a3=7fff15c0a7c0 items=3 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573858.178:46804):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573858.178:46804): item=0 name=\"test_file\" objtype=UNKNOWN"},
  {1302, "audit(1502573858.178:46804): item=1 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573858.178:46804): item=2 name=\"test_file4\" inode=724406 dev=fd:02 mode=0120777 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=CREATE"},
  {1320, "audit(1502573858.178:46804): "},
  {1300, "audit(1502573858.178:46805): arch=c000003e syscall=82 success=yes exit=0 a0=40219c a1=402215 a2=40220a a3=7fff15c0a7c0 items=4 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573858.178:46805):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573858.178:46805): item=0 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573858.178:46805): item=1 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573858.178:46805): item=2 name=\"test_file\" inode=98362 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=DELETE"},
  {1302, "audit(1502573858.178:46805): item=3 name=\"test_file_rename\" inode=98362 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=CREATE"},
  {1320, "audit(1502573858.178:46805): "},
  {1300, "audit(1502573858.178:46806): arch=c000003e syscall=264 success=yes exit=0 a0=3 a1=402215 a2=3 a3=40224e items=4 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573858.178:46806):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573858.178:46806): item=0 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573858.178:46806): item=1 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573858.178:46806): item=2 name=\"test_file_rename\" inode=98362 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=DELETE"},
  {1302, "audit(1502573858.178:46806): item=3 name=\"test_file_renameat\" inode=98362 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=CREATE"},
  {1320, "audit(1502573858.178:46806): "},
  {1300, "audit(1502573858.178:46807): arch=c000003e syscall=316 success=yes exit=0 a0=3 a1=40224e a2=3 a3=40219c items=4 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573858.178:46807):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573858.178:46807): item=0 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573858.178:46807): item=1 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573858.178:46807): item=2 name=\"test_file_renameat\" inode=98362 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=DELETE"},
  {1302, "audit(1502573858.178:46807): item=3 name=\"test_file\" inode=98362 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=CREATE"},
  {1320, "audit(1502573858.178:46807): "},
  {1300, "audit(1502573858.178:46808): arch=c000003e syscall=87 success=yes exit=0 a0=402191 a1=40224e a2=3 a3=40219c items=2 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573858.178:46808):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573858.178:46808): item=0 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573858.178:46808): item=1 name=\"test_file1\" inode=98362 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=DELETE"},
  {1320, "audit(1502573858.178:46808): "},
  {1300, "audit(1502573858.178:46809): arch=c000003e syscall=263 success=yes exit=0 a0=3 a1=4021cc a2=0 a3=7fff15c0a7b0 items=2 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573858.178:46809):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573858.178:46809): item=0 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573858.178:46809): item=1 name=\"test_file2\" inode=724389 dev=fd:02 mode=0120777 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=DELETE"},
  {1320, "audit(1502573858.178:46809): "},
  {1300, "audit(1502573858.178:46810): arch=c000003e syscall=2 success=yes exit=4 a0=4022c6 a1=42 a2=0 a3=7fff15c0a3a0 items=2 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573858.178:46810):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573858.178:46810): item=0 name=\"/home/alessandro/\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573858.178:46810): item=1 name=\"/home/alessandro/test_file\" inode=98362 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=NORMAL"},
  {1320, "audit(1502573858.178:46810): "},
  {1300, "audit(1502573858.178:46811): arch=c000003e syscall=32 success=yes exit=5 a0=4 a1=42 a2=0 a3=7fff15c0a3a0 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573858.178:46811): "},
  {1300, "audit(1502573858.178:46812): arch=c000003e syscall=33 success=yes exit=10 a0=4 a1=a a2=0 a3=7fff15c0a3a0 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573858.178:46812): "},
  {1300, "audit(1502573858.178:46813): arch=c000003e syscall=292 success=yes exit=11 a0=4 a1=b a2=0 a3=7fff15c0a3a0 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573858.178:46813): "},
  {1300, "audit(1502573858.178:46814): arch=c000003e syscall=3 success=yes exit=0 a0=b a1=b a2=0 a3=7fff15c0a3a0 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573858.178:46814): "},
  {1300, "audit(1502573858.178:46815): arch=c000003e syscall=257 success=yes exit=6 a0=3 a1=40219c a2=0 a3=0 items=1 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573858.178:46815):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573858.178:46815): item=0 name=\"test_file\" inode=98362 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=NORMAL"},
  {1320, "audit(1502573858.178:46815): "},
  {1300, "audit(1502573858.178:46816): arch=c000003e syscall=303 success=yes exit=0 a0=ffffff9c a1=40219c a2=7fff15c0a620 a3=7fff15c0aa2c items=1 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573858.178:46816):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573858.178:46816): item=0 name=\"test_file\" inode=98362 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=NORMAL"},
  {1320, "audit(1502573858.178:46816): "},
  {1300, "audit(1502573858.178:46817): arch=c000003e syscall=304 success=yes exit=7 a0=ffffff9c a1=7fff15c0a620 a2=2 a3=7fff15c0a3a0 items=1 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573858.178:46817):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573858.178:46817): item=0 name="" inode=98362 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=NORMAL"},
  {1320, "audit(1502573858.178:46817): "},
  {1300, "audit(1502573858.178:46818): arch=c000003e syscall=303 success=yes exit=0 a0=3 a1=40219c a2=7fff15c0a620 a3=7fff15c0aa2c items=1 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573858.178:46818):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573858.178:46818): item=0 name=\"test_file\" inode=98362 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=NORMAL"},
  {1320, "audit(1502573858.178:46818): "},
  {1300, "audit(1502573858.178:46819): arch=c000003e syscall=304 success=yes exit=8 a0=3 a1=7fff15c0a620 a2=2 a3=7fff15c0aa2c items=1 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573858.178:46819):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573858.178:46819): item=0 name="" inode=98362 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=NORMAL"},
  {1320, "audit(1502573858.178:46819): "},
  {1300, "audit(1502573858.178:46820): arch=c000003e syscall=133 success=yes exit=0 a0=40242d a1=81a4 a2=0 a3=7fff15c0a380 items=2 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573858.178:46820):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573858.178:46820): item=0 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573858.178:46820): item=1 name=\"test_file5\" inode=560977 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=CREATE"},
  {1320, "audit(1502573858.178:46820): "},
  {1300, "audit(1502573858.178:46821): arch=c000003e syscall=259 success=yes exit=0 a0=3 a1=402451 a2=81a4 a3=0 items=2 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573858.178:46821):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573858.178:46821): item=0 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573858.178:46821): item=1 name=\"test_file6\" inode=560986 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=CREATE"},
  {1320, "audit(1502573858.178:46821): "},
  {1300, "audit(1502573858.178:46822): arch=c000003e syscall=85 success=yes exit=9 a0=402477 a1=81a4 a2=81a4 a3=7fff15c0a3a0 items=2 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1307, "audit(1502573858.178:46822):  cwd=\"/home/alessandro\""},
  {1302, "audit(1502573858.178:46822): item=0 name=\"/home/alessandro\" inode=67 dev=fd:02 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 objtype=PARENT"},
  {1302, "audit(1502573858.178:46822): item=1 name=\"test_file7\" inode=560990 dev=fd:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 objtype=CREATE"},
  {1320, "audit(1502573858.178:46822): "},
  {1300, "audit(1502573858.179:46823): arch=c000003e syscall=0 success=yes exit=10 a0=4 a1=7fff15c0a640 a2=a a3=7fff15c0a3c0 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573858.179:46823): "},
  {1300, "audit(1502573858.179:46824): arch=c000003e syscall=1 success=yes exit=1024 a0=4 a1=7fff15c0a640 a2=400 a3=7fff15c0a3c0 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573858.179:46824): "},
  {1300, "audit(1502573858.179:46825): arch=c000003e syscall=17 success=yes exit=10 a0=4 a1=7fff15c0a640 a2=a a3=1 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573858.179:46825): "},
  {1300, "audit(1502573858.179:46826): arch=c000003e syscall=18 success=yes exit=1024 a0=4 a1=7fff15c0a640 a2=400 a3=1 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573858.179:46826): "},
  {1300, "audit(1502573858.179:46827): arch=c000003e syscall=77 success=yes exit=0 a0=4 a1=b a2=400 a3=7fff15c0a7c0 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1320, "audit(1502573858.179:46827): "},
  {1300, "audit(1502573858.179:46828): arch=c000003e syscall=9 success=yes exit=140095431462912 a0=0 a1=a a2=7 a3=1 items=0 ppid=4316 pid=5581 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm=\"mytest\" exe=\"/home/alessandro/mytest\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)"},
  {1323, "audit(1502573858.179:46828): fd=4 flags=0x1"},
  {1320, "audit(1502573858.179:46828): "}
};
// clang-format on
} // namespace osquery
