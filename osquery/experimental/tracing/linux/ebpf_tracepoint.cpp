/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/experimental/tracing/linux/ebpf_tracepoint.h>

#include <osquery/utils/expected/expected.h>
#include <osquery/utils/system/linux/perf_event/perf_event.h>

#include <osquery/logger/logger.h>

#include <boost/io/detail/quoted_manip.hpp>

#include <sys/ioctl.h>

namespace osquery {
namespace events {

EbpfTracepoint::EbpfTracepoint(tracing::NativeEvent system_event,
                               ebpf::Program program)
    : system_event_{std::move(system_event)}, program_{std::move(program)} {}

EbpfTracepoint::EbpfTracepoint(EbpfTracepoint&& other)
    : fd_{other.fd_},
      system_event_{std::move(other.system_event_)},
      program_{std::move(other.program_)} {
  other.fd_ = -1;
}

EbpfTracepoint& EbpfTracepoint::operator=(EbpfTracepoint&& other) {
  std::swap(system_event_, other.system_event_);
  std::swap(program_, other.program_);
  std::swap(fd_, other.fd_);
  return *this;
}

EbpfTracepoint::~EbpfTracepoint() {
  forceUnload();
}

Expected<EbpfTracepoint, EbpfTracepoint::Error> EbpfTracepoint::load(
    tracing::NativeEvent system_event, ebpf::Program program) {
  auto instance = EbpfTracepoint(std::move(system_event), std::move(program));

  struct perf_event_attr trace_attr;
  memset(&trace_attr, 0, sizeof(struct perf_event_attr));
  trace_attr.type = PERF_TYPE_TRACEPOINT;
  trace_attr.size = sizeof(struct perf_event_attr);
  trace_attr.config = instance.system_event_.id();
  trace_attr.sample_period = 1;
  trace_attr.sample_type = PERF_SAMPLE_RAW;
  trace_attr.wakeup_events = 1;
  trace_attr.disabled = 1;

  pid_t const pid = -1;
  int const cpu = 0;
  int const group_fd = -1;
  unsigned long const flags = PERF_FLAG_FD_CLOEXEC;
  auto fd_exp =
      perf_event_open::syscall(&trace_attr, pid, cpu, group_fd, flags);
  if (fd_exp.isError()) {
    return createError(Error::SystemError, fd_exp.takeError())
           << "Fail to create perf_event tracepoint";
  }
  instance.fd_ = fd_exp.take();

  if (ioctl(instance.fd_, PERF_EVENT_IOC_SET_BPF, instance.program_.fd()) < 0) {
    return createError(Error::SystemError)
           << "Fail to attach perf event of EbpfTracepoint "
           << boost::io::quoted(strerror(errno));
  }
  if (ioctl(instance.fd_, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    return createError(Error::SystemError)
           << "Fail to enable perf event of EbpfTracepoint "
           << boost::io::quoted(strerror(errno));
  }
  return std::move(instance);
}

ExpectedSuccess<EbpfTracepoint::Error> EbpfTracepoint::unload() {
  if (fd_ < 0) {
    return Success{};
  }
  bool failed = false;
  std::string err_msg;
  int ret = ioctl(fd_, PERF_EVENT_IOC_DISABLE, 0);
  if (ret < 0) {
    failed = true;
    err_msg += " perf event disabling failed: \"";
    err_msg += strerror(errno);
    err_msg += "\". ";
  }
  ret = close(fd_);
  if (ret < 0) {
    failed = true;
    err_msg += " file descriptor closed with error: \"";
    err_msg += strerror(errno);
    err_msg += "\".";
  }
  fd_ = -1;
  if (failed) {
    return createError(Error::SystemError)
           << "EbpfTracepoint unload failed " << err_msg;
  }
  return Success{};
}

void EbpfTracepoint::forceUnload() {
  auto const exp = unload();
  if (exp.isError()) {
    LOG(ERROR) << "Could not unload perf tracepoint "
               << boost::io::quoted(exp.getError().getMessage());
  }
}

} // namespace events
} // namespace osquery
