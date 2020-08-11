/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/experimental/tracing/linux/probes.h>

#include <osquery/utils/expected/expected.h>
#include <osquery/utils/map_take.h>
#include <osquery/utils/system/linux/cpu.h>
#include <osquery/utils/system/linux/perf_event/perf_event.h>
#include <osquery/utils/system/posix/errno.h>

#include <osquery/logger/logger.h>

#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/time.h>

namespace osquery {
namespace events {

namespace {

Expected<std::string, LinuxProbesControl::Error> toTracingPath(
    syscall::EventType type) {
  static const auto table =
      std::unordered_map<syscall::EventType, std::string, EnumClassHash>{
          {syscall::EventType::KillEnter, "syscalls/sys_enter_kill"},
          {syscall::EventType::KillExit, "syscalls/sys_exit_kill"},
          {syscall::EventType::SetuidEnter, "syscalls/sys_enter_setuid"},
          {syscall::EventType::SetuidExit, "syscalls/sys_exit_setuid"},
      };
  auto exp = tryTakeCopy(table, type);
  if (exp.isError()) {
    return createError(LinuxProbesControl::Error::InvalidArgument,
                       exp.takeError())
           << "unknown tracing event path for type " << to<std::string>(type);
  }
  return exp.take();
}

size_t constexpr kMemoryLockSize = 266240u;

ExpectedSuccess<PosixError> setMemoryLockSystemLimit() {
  struct rlimit limits = {RLIM_INFINITY, RLIM_INFINITY};
  auto ret = setrlimit(RLIMIT_MEMLOCK, &limits);
  if (ret < 0) {
    return createError(to<PosixError>(errno))
           << "setrlimit() syscall failed: "
           << boost::io::quoted(strerror(errno));
  }
  return Success{};
}

} // namespace

LinuxProbesControl::LinuxProbesControl(
    PerfEventCpuMap cpu_to_perf_output_map,
    ebpf::PerfOutputsPoll<events::syscall::Event> output_poll)
    : cpu_to_perf_output_map_(std::move(cpu_to_perf_output_map)),
      output_poll_(std::move(output_poll)) {}

Expected<LinuxProbesControl, LinuxProbesControl::Error>
LinuxProbesControl::spawn() {
  auto exp = setMemoryLockSystemLimit();
  if (exp.isError()) {
    return createError(Error::SystemUnknown, exp.takeError())
           << "failed to set appropriate memory lock limits";
  }

  auto cpu_map_exp =
      ebpf::createMap<int, int, BPF_MAP_TYPE_PERF_EVENT_ARRAY>(cpu::kMaskSize);
  if (cpu_map_exp.isError()) {
    return createError(Error::SystemEbpf, cpu_map_exp.takeError())
           << "failed to create eBPF map for {cpu -> perf} table";
  }
  auto cpu_map = cpu_map_exp.take();

  auto output_poll = ebpf::PerfOutputsPoll<events::syscall::Event>{};
  auto online_cpu_exp = cpu::getOnline();
  if (online_cpu_exp.isError()) {
    return createError(Error::SystemUnknown, online_cpu_exp.takeError())
           << "failed to load cpu configuration";
  }
  auto const online_cpu = online_cpu_exp.take();
  for (auto cpu_i = std::size_t{0}; cpu_i < online_cpu.size(); ++cpu_i) {
    if (online_cpu.test(cpu_i)) {
      auto output_exp = ebpf::PerfOutput<events::syscall::Event>::load(
          cpu_i, kMemoryLockSize);
      if (output_exp.isError()) {
        return createError(Error::SystemPerfEvent, output_exp.takeError())
               << "perf events output initialisation failed";
      }
      {
        auto status = cpu_map.updateElement(cpu_i, output_exp->fd());
        if (status.isError()) {
          return createError(Error::SystemEbpf, status.takeError())
                 << "loading perf events output to map failed";
        }
      }
      {
        auto status = output_poll.add(output_exp.take());
        if (status.isError()) {
          return createError(Error::SystemUnknown, status.takeError())
                 << "adding new output to PerfOutputsPoll failed";
        }
      }
    }
  }
  return LinuxProbesControl(std::move(cpu_map), std::move(output_poll));
}

ebpf::PerfOutputsPoll<events::syscall::Event>& LinuxProbesControl::getReader() {
  return output_poll_;
}

namespace {

Expected<EbpfTracepoint, LinuxProbesControl::Error> createTracepointForSyscall(
    syscall::EventType type, PerfEventCpuMap const& cpu_map) {
  auto program_exp = genLinuxProgram(BPF_PROG_TYPE_TRACEPOINT, cpu_map, type);
  if (program_exp.isError()) {
    return createError(LinuxProbesControl::Error::SystemEbpf,
                       program_exp.takeError())
           << "could not load program to track syscall "
           << to<std::string>(type);
  }
  auto tracing_path_exp = toTracingPath(type);
  if (tracing_path_exp.isError()) {
    return createError(LinuxProbesControl::Error::InvalidArgument,
                       tracing_path_exp.takeError());
  }
  auto sys_event_exp = tracing::NativeEvent::load(tracing_path_exp.take());
  if (sys_event_exp.isError()) {
    return createError(LinuxProbesControl::Error::SystemNativeEvent,
                       sys_event_exp.takeError())
           << "could not enable linux event for " << to<std::string>(type);
  }
  auto tracepoint_exp =
      events::EbpfTracepoint::load(sys_event_exp.take(), program_exp.take());
  if (tracepoint_exp.isError()) {
    return createError(LinuxProbesControl::Error::SystemTracepoint,
                       tracepoint_exp.takeError())
           << "could not attach tracing prograp to the native event of "
           << to<std::string>(type);
  }
  return tracepoint_exp.take();
}

} // namespace

ExpectedSuccess<LinuxProbesControl::Error>
LinuxProbesControl::traceEnterAndExit(syscall::EventType type) {
  if (type == syscall::EventType::Unknown) {
    return createError(Error::InvalidArgument)
           << "Wrong syscall type: 'Unknown'";
  }
  auto tracepoint_exp =
      createTracepointForSyscall(type, cpu_to_perf_output_map_);
  if (tracepoint_exp.isValue()) {
    auto const inv_type = syscall::flipEventType(type);
    auto inv_tracepoint_exp =
        createTracepointForSyscall(inv_type, cpu_to_perf_output_map_);
    if (inv_tracepoint_exp.isValue()) {
      probes_.emplace(type, tracepoint_exp.take());
      probes_.emplace(inv_type, inv_tracepoint_exp.take());
      return Success{};
    } else {
      return inv_tracepoint_exp.takeError();
    }
  }
  return tracepoint_exp.takeError();
}

ExpectedSuccess<LinuxProbesControl::Error> LinuxProbesControl::traceKill() {
  return traceEnterAndExit(syscall::EventType::KillEnter);
}

ExpectedSuccess<LinuxProbesControl::Error> LinuxProbesControl::traceSetuid() {
  return traceEnterAndExit(syscall::EventType::SetuidEnter);
}

} // namespace events
} // namespace osquery
