/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <iostream>

#include <benchmark/benchmark.h>

#include <osquery/sql.h>

#include "osquery/events/linux/auditeventpublisher.h"
#include "osquery/tables/events/linux/process_events.h"
#include "osquery/tables/events/linux/socket_events.h"
#include "osquery/tables/events/linux/user_events.h"
#include "osquery/tests/test_util.h"

namespace osquery {
// clang-format off
const std::vector<std::pair<int, std::string>> kSampleExecEvent = {
  {1300, "audit(1528879754.076:123): arch=c000003e syscall=59 success=yes exit=0 a0=55d185ac4b18 a1=55d185ac4b50 a2=55d185ac4b68 a3=1 items=2 ppid=5540 pid=5541 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"ls\" exe=\"/bin/ls\" key=(null)"},
  {1309, "audit(1528879754.076:123): argc=2 a0=\"/bin/ls\" a1=\"/\""},
  {1307, "audit(1528879754.076:123): cwd=\"/\""},
  {1302, "audit(1528879754.076:123): item=0 name=\"/bin/ls\" inode=786515 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0"},
  {1302, "audit(1528879754.076:123): item=1 name=\"/lib64/ld-linux-x86-64.so.2\" inode=1577569 dev=08:01 mode=0100755 ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0"},
  {1327, "audit(1528879754.076:123): proctitle=2F62696E2F6C73002F"},
  {1320, "audit(1528879754.076:123): "}
};
// clang-format on

// clang-format off
const std::vector<std::pair<int, std::string>> kSampleConnectEvent = {
  {1300, "audit(1528888648.161:253): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=ff5530 a2=10 a3=0 items=0 ppid=28769 pid=29036 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=5 comm=\"nc\" exe=\"/bin/nc.openbsd\" key=(null)"},
  {1306, "audit(1528888648.161:253): saddr=020001BBBFEFD5C50000000000000000"},
  {1327, "audit(1528888648.161:253): proctitle=6E63006D73646E2E636F6D00343433"},
  {1320, "audit(1528888648.161:253): "}
};
// clang-format on

// clang-format off
const std::vector<std::pair<int, std::string>> kSampleSudoEvent = {
  {1106, "audit(1528937759.256:303): pid=37819 uid=0 auid=1000 ses=23 msg='op=PAM:session_close acct=\"root\" exe=\"/usr/bin/sudo\" hostname=? addr=? terminal=/dev/pts/3 res=success'"},
  {1104, "audit(1528937759.256:304): pid=37819 uid=0 auid=1000 ses=23 msg='op=PAM:setcred acct=\"root\" exe=\"/usr/bin/sudo\" hostname=? addr=? terminal=/dev/pts/3 res=success'"},
  {1123, "audit(1528937760.278:305): pid=37927 uid=1000 auid=1000 ses=23 msg='cwd=\"/home/osquery\" cmd=\"bash\" terminal=pts/3 res=success'"},
  {1110, "audit(1528937760.278:306): pid=37927 uid=0 auid=1000 ses=23 msg='op=PAM:setcred acct=\"root\" exe=\"/usr/bin/sudo\" hostname=? addr=? terminal=/dev/pts/3 res=success'"},
  {1105, "audit(1528937760.279:307): pid=37927 uid=0 auid=1000 ses=23 msg='op=PAM:session_open acct=\"root\" exe=\"/usr/bin/sudo\" hostname=? addr=? terminal=/dev/pts/3 res=success'"}
};
// clang-format on

static void parseAuditEventRecord(AuditEventRecord& audit_event_record,
                                  int audit_record_type,
                                  std::string audit_message_copy) {
  audit_reply reply = {};
  reply.type = audit_record_type;
  reply.len = audit_message_copy.size();
  reply.message = &audit_message_copy[0];

  if (!AuditdNetlinkParser::ParseAuditReply(reply, audit_event_record)) {
    throw std::runtime_error("Failed to parse the audit record");
  }
}

static void generateEventContext(
    std::shared_ptr<AuditEventContext>& event_context,
    AuditTraceContext& trace_context,
    size_t event_count,
    const std::vector<std::pair<int, std::string>> sample_data) {
  std::vector<AuditEventRecord> data_set;
  auto data_set_size = sample_data.size() * event_count;

  data_set.reserve(data_set_size);
  if (data_set.capacity() != data_set_size) {
    throw std::bad_alloc();
  }

  for (size_t i = 0; i < event_count; i++) {
    for (const auto& record_descriptor : sample_data) {
      AuditEventRecord audit_event_record;
      parseAuditEventRecord(audit_event_record,
                            record_descriptor.first,
                            record_descriptor.second);

      data_set.push_back(audit_event_record);
    }
  }

  event_context = std::make_shared<AuditEventContext>();
  trace_context = {};

  AuditEventPublisher::ProcessEvents(event_context, data_set, trace_context);
}

static void AUDIT_recordParsingBenchmark(benchmark::State& state) {
  auto event_count = static_cast<std::size_t>(state.range(0));

  for (auto _ : state) {
    for (size_t i = 0U; i < event_count; i++) {
      for (const auto& record_descriptor : kSampleExecEvent) {
        AuditEventRecord audit_event_record;
        parseAuditEventRecord(audit_event_record,
                              record_descriptor.first,
                              record_descriptor.second);
      }
    }
  }

  state.SetItemsProcessed(state.iterations() * event_count);
}

BENCHMARK(AUDIT_recordParsingBenchmark)
    ->Unit(benchmark::kMillisecond)
    ->Arg(5000);

static void AUDIT_recordProcessingBenchmark(benchmark::State& state) {
  auto event_count = static_cast<std::size_t>(state.range(0));

  for (auto _ : state) {
    std::shared_ptr<AuditEventContext> event_context;
    AuditTraceContext audit_trace_context;
    generateEventContext(
        event_context, audit_trace_context, event_count, kSampleExecEvent);
  }

  state.SetItemsProcessed(state.iterations() * event_count);
}

BENCHMARK(AUDIT_recordProcessingBenchmark)
    ->Unit(benchmark::kMillisecond)
    ->Arg(5000);

// clang-format off
#define DeclareAuditBenchmark(name, sample_data, emitter)                                   \
  static void AUDIT_ ## name ## Benchmark(benchmark::State& state) {                        \
    auto event_count = static_cast<std::size_t>(state.range(0));                            \
                                                                                            \
    for (auto _ : state) {                                                                  \
      std::shared_ptr<AuditEventContext> event_context;                                     \
      AuditTraceContext audit_trace_context;                                                \
      generateEventContext(event_context, audit_trace_context, event_count, sample_data);   \
                                                                                            \
      std::vector<osquery::Row> emitted_row_list;                                           \
      emitter(emitted_row_list, event_context->audit_events);                               \
    }                                                                                       \
                                                                                            \
    state.SetItemsProcessed(state.iterations() * event_count);                              \
  }                                                                                         \
                                                                                            \
  BENCHMARK(AUDIT_ ## name ## Benchmark)                                                    \
    ->Unit(benchmark::kMillisecond)                                                         \
    ->Arg(5000);
// clang-format on

// clang-format off
DeclareAuditBenchmark(processEvents, kSampleExecEvent, AuditProcessEventSubscriber::ProcessEvents)
DeclareAuditBenchmark(socketEvents, kSampleConnectEvent, SocketEventSubscriber::ProcessEvents)
DeclareAuditBenchmark(userEvents, kSampleSudoEvent, UserEventSubscriber::ProcessEvents)
// clang-format on
} // namespace osquery
