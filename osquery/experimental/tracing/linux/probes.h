/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/experimental/tracing/linux/ebpf_tracepoint.h>
#include <osquery/experimental/tracing/linux/syscall_event.h>
#include <osquery/experimental/tracing/linux/syscalls_programs.h>

#include <osquery/utils/enum_class_hash.h>
#include <osquery/utils/expected/expected.h>
#include <osquery/utils/system/linux/ebpf/perf_output.h>

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

  static Expected<LinuxProbesControl, LinuxProbesControl::Error> spawn();

  ebpf::PerfOutputsPoll<events::syscall::Event>& getReader();

  ExpectedSuccess<Error> traceKill();
  ExpectedSuccess<Error> traceSetuid();

 private:
  using PerfEventCpuMap = ebpf::Map<int, int, BPF_MAP_TYPE_PERF_EVENT_ARRAY>;

  explicit LinuxProbesControl(
      PerfEventCpuMap cpu_to_perf_output_map,
      ebpf::PerfOutputsPoll<events::syscall::Event> output_poll);

  ExpectedSuccess<Error> traceEnterAndExit(syscall::EventType type);

 private:
  std::unordered_map<syscall::EventType, EbpfTracepoint, EnumClassHash> probes_;
  PerfEventCpuMap cpu_to_perf_output_map_;
  ebpf::PerfOutputsPoll<events::syscall::Event> output_poll_;
};

} // namespace events
} // namespace osquery
