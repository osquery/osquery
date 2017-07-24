/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <map>

#include <benchmark/benchmark.h>

#include <osquery/events.h>

#include "osquery/events/linux/audit.h"
#include "osquery/events/linux/auditnetlink.h"

namespace osquery {

/// This is a poor interface.
extern bool ProcessUpdate(size_t, const AuditFields&, AuditFields&);

const std::vector<std::string> kBenchmarkMessages = {
    "audit(1480751147.912:48372): arch=c000003e syscall=59 success=yes exit=0 "
    "a0=7ffede628b50 a1=7f1779ccb140 a2=25c6740 a3=598 items=2 ppid=8422 "
    "pid=8423 auid=4294967295 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 "
    "egid=1000 sgid=1000 fsgid=1000 tty=pts20 ses=4294967295 comm=\"git\" "
    "exe=\"/usr/bin/git\" key=(null)",
    "audit(1480751147.912:48372): argc=4 a0=\"git\" a1=\"config\" a2=\"--get\" "
    "a3=\"oh-my-zsh.hide-status\"",
    "audit(1480751147.912:48372):  cwd=\"/home/osquery\"",
    "audit(1480751147.912:48372): item=0 name=\"/usr/bin/git\" inode=7866334 "
    "dev=fc:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL",
    "audit(1480751147.912:48372): item=1 name=\"/lib64/ld-linux-x86-64.so.2\" "
    "inode=10879894 dev=fc:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 "
    "nametype=NORMAL",
    "audit(1480751147.912:48372): "
    "proctitle="
    "67697400636F6E666967002D2D676574006F682D6D792D7A73682E686964652D7374617475"
    "73",
};

struct audit_reply getMockReply(const std::string& message) {
  struct audit_reply reply;

  reply.type = 1;
  reply.len = message.size();
  reply.message = (char*)malloc(sizeof(char) * (message.size() + 1));
  memset((void*)reply.message, 0, message.size() + 1);
  memcpy((void*)reply.message, message.c_str(), message.size());

  return reply;
}

static void AUDIT_handleReply(benchmark::State& state) {
  auto reply = getMockReply(kBenchmarkMessages[0]);

  while (state.KeepRunning()) {
    AuditEventRecord audit_event_record = {};
    AuditNetlink::ParseAuditReply(reply, audit_event_record);
  }

  free((void*)reply.message);
}

BENCHMARK(AUDIT_handleReply);

static void AUDIT_assembler(benchmark::State& state) {
  AuditAssembler asmb;
  asmb.start(
      20, {AUDIT_SYSCALL, AUDIT_EXECVE, AUDIT_PATH, AUDIT_CWD}, &ProcessUpdate);

  std::vector<struct audit_reply> replies = {
      getMockReply(kBenchmarkMessages[0]),
      getMockReply(kBenchmarkMessages[1]),
      getMockReply(kBenchmarkMessages[2]),
      getMockReply(kBenchmarkMessages[3]),
      getMockReply(kBenchmarkMessages[4]),
      getMockReply(kBenchmarkMessages[5]),
  };

  std::vector<AuditEventRecord> contexts;
  for (const auto& r : replies) {
    AuditEventRecord audit_event_record = {};
    AuditNetlink::ParseAuditReply(r, audit_event_record);

    contexts.push_back(audit_event_record);
  }

  size_t i = 0;
  while (state.KeepRunning()) {
    const auto& ec = contexts[i++ % 6];
    asmb.add(ec.audit_id, ec.type, ec.fields);
  }

  for (auto& r : replies) {
    free((void*)r.message);
  }
}

BENCHMARK(AUDIT_assembler);
}
