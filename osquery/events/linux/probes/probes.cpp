/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/events/linux/probes/probes.h>

#include <osquery/utils/expected/expected.h>
#include <osquery/utils/map_take.h>
#include <osquery/utils/system/linux/perf_event/perf_event.h>

#include <osquery/logger.h>

#include <sys/ioctl.h>

namespace osquery {
namespace events {

namespace {

Expected<std::string, LinuxProbesControl::Error> toTracingPath(
    syscall::Type type) {
  static const auto table =
      std::unordered_map<syscall::Type, std::string, EnumClassHash>{
          {syscall::Type::KillEnter, "syscalls/sys_enter_kill"},
          {syscall::Type::KillExit, "syscalls/sys_exit_kill"},
          {syscall::Type::SetuidEnter, "syscalls/sys_enter_setuid"},
          {syscall::Type::SetuidExit, "syscalls/sys_exit_setuid"},
      };
  auto exp = tryTakeCopy(table, type);
  if (exp.isError()) {
    return createError(LinuxProbesControl::Error::InvalidArgument,
                       "unknown tracing event path for type ",
                       exp.takeError())
           << to<std::string>(type);
  }
  return exp.take();
}

Expected<EbpfTracepoint, LinuxProbesControl::Error> createTracepointForSyscall(
    syscall::Type type, PerfEventCpuMap const& cpu_map) {
  auto program_exp = genLinuxProgram(BPF_PROG_TYPE_TRACEPOINT, cpu_map, type);
  if (program_exp.isError()) {
    return createError(LinuxProbesControl::Error::SystemEbpf,
                       "could not load program to track syscall ",
                       program_exp.takeError())
           << to<std::string>(type);
  }
  auto tracing_path_exp = toTracingPath(type);
  if (tracing_path_exp.isError()) {
    return createError(LinuxProbesControl::Error::InvalidArgument,
                       "",
                       tracing_path_exp.takeError());
  }
  auto sys_event_exp = tracing::NativeEvent::load(tracing_path_exp.take());
  if (sys_event_exp.isError()) {
    return createError(LinuxProbesControl::Error::SystemNativeEvent,
                       "could not enable linux event for ",
                       sys_event_exp.takeError())
           << to<std::string>(type);
  }
  auto tracepoint_exp =
      events::EbpfTracepoint::load(sys_event_exp.take(), program_exp.take());
  if (tracepoint_exp.isError()) {
    return createError(
               LinuxProbesControl::Error::SystemTracepoint,
               "could not attach tracing prograp to the native event of ",
               tracepoint_exp.takeError())
           << to<std::string>(type);
  }
  return tracepoint_exp.take();
}

} // namespace

ExpectedSuccess<LinuxProbesControl::Error>
LinuxProbesControl::traceEnterAndExit(syscall::Type type,
                                      PerfEventCpuMap const& cpu_map) {
  auto tracepoint_exp = createTracepointForSyscall(type, cpu_map);
  if (tracepoint_exp.isValue()) {
    auto const inv_type = syscall::flipType(type);
    auto inv_tracepoint_exp = createTracepointForSyscall(inv_type, cpu_map);
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

ExpectedSuccess<LinuxProbesControl::Error> LinuxProbesControl::traceKill(
    PerfEventCpuMap const& cpu_map) {
  return traceEnterAndExit(syscall::Type::KillEnter, cpu_map);
}

ExpectedSuccess<LinuxProbesControl::Error> LinuxProbesControl::traceSetuid(
    PerfEventCpuMap const& cpu_map) {
  return traceEnterAndExit(syscall::Type::SetuidEnter, cpu_map);
}

} // namespace events
} // namespace osquery
