/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#pragma once

#include <osquery/events/linux/probes/ebpf_tracepoint.h>
#include <osquery/events/linux/probes/syscall_event.h>
#include <osquery/events/linux/probes/syscalls_programs.h>

#include <osquery/utils/enum_class_hash.h>
#include <osquery/utils/expected/expected.h>

namespace osquery {
namespace events {

class LinuxProbesControl final {
 public:
  enum class Error {
    SystemUnknown = 1,
    SystemEbpf = 2,
    SystemNativeEvent = 3,
    SystemTracepoint = 4,
    SystemPerfEvent = 5,
    InvalidArgument = 6,
  };

  using PerfEventCpuMap = ebpf::Map<int, int, BPF_MAP_TYPE_PERF_EVENT_ARRAY>;

  ExpectedSuccess<Error> traceKill(PerfEventCpuMap const& cpu_map);
  ExpectedSuccess<Error> traceSetuid(PerfEventCpuMap const& cpu_map);

 private:
  ExpectedSuccess<Error> traceEnterAndExit(syscall::Type type,
                                           PerfEventCpuMap const& cpu_map);

 private:
  std::unordered_map<syscall::Type, EbpfTracepoint, EnumClassHash> probes_;
};

} // namespace events
} // namespace osquery
