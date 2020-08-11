/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/experimental/tracing/syscalls_tracing_impl.h>

#include <osquery/experimental/events_stream/events_stream.h>
#include <osquery/experimental/tracing/linux/probes.h>

#include <osquery/dispatcher/dispatcher.h>
#include <osquery/logger/logger.h>

#include <osquery/utils/caches/lru.h>
#include <osquery/utils/expected/expected.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/system/linux/proc/proc.h>
#include <osquery/utils/system/time.h>

namespace osquery {
namespace events {

namespace {

class ProcCmdlineRetriever {
 public:
  // This is experimentally obtained number for the command line strings
  // preserved in cache. If you need to decrease number of cache misses or to
  // decrease memory consumption don't be shy to change it.
  static constexpr auto kCacheCapacity = std::size_t{256};

  explicit ProcCmdlineRetriever() : cache_(kCacheCapacity) {}

  std::string const& get(pid_t proc_pid) {
    if (auto cmd_ptr = cache_.get(proc_pid)) {
      return *cmd_ptr;
    } else {
      return *cache_.insert(proc_pid, proc::cmdline(proc_pid));
    }
  }

 private:
  caches::LRU<pid_t, std::string> cache_;
};

enum class Error {
  InitialisationProblem = 1,
  RuntimeProblem = 2,
  DeinitializationProblem = 3,
};

ExpectedSuccess<Error> runSyscallTracing() {
  auto probes_exp = ::osquery::events::LinuxProbesControl::spawn();
  if (probes_exp.isError()) {
    return createError(Error::InitialisationProblem, probes_exp.takeError())
           << "linux probes control spawn failed";
  }
  auto probes = probes_exp.take();
  auto kill_trace_on_exp = probes.traceKill();
  if (kill_trace_on_exp.isError()) {
    return createError(Error::InitialisationProblem,
                       kill_trace_on_exp.takeError())
           << "kill tracing initialisation failed";
  }
  auto setuid_trace_on_exp = probes.traceSetuid();
  if (setuid_trace_on_exp.isError()) {
    return createError(Error::InitialisationProblem,
                       setuid_trace_on_exp.takeError())
           << "setuid tracing initialisation failed";
  }
  auto output_batch = ebpf::PerfOutputsPoll<
      ::osquery::events::syscall::Event>::MessageBatchType{};
  auto event_joiner = ::osquery::events::syscall::EnterExitJoiner{};
  auto cmdline_getter = ProcCmdlineRetriever{};
  while (true) {
    auto status = probes.getReader().read(output_batch);
    if (status.isError()) {
      return createError(Error::RuntimeProblem, status.takeError())
             << "event read failed";
    }
    for (const auto& event : output_batch) {
      auto final_event = event_joiner.join(event);
      if (final_event) {
        auto event_json = JSON{};
        auto event_str = std::string{};
        event_json.add("time", getUnixTime());
        event_json.add("pid", final_event->pid);
        event_json.add("tgid", final_event->tgid);
        event_json.add("cmdline", cmdline_getter.get(final_event->pid));
        event_json.add("return", final_event->return_value);
        if (final_event->type ==
            ::osquery::events::syscall::EventType::KillEnter) {
          event_json.add("type", "kill");
          event_json.add("uid", final_event->body.kill_enter.uid);
          event_json.add("gid", final_event->body.kill_enter.gid);
          event_json.add("comm", final_event->body.kill_enter.comm);
          event_json.add("arg_pid", final_event->body.kill_enter.arg_pid);
          event_json.add(
              "arg_cmdline",
              cmdline_getter.get(final_event->body.kill_enter.arg_pid));
          event_json.add("arg_sig", final_event->body.kill_enter.arg_sig);
        } else if (final_event->type ==
                   ::osquery::events::syscall::EventType::SetuidEnter) {
          event_json.add("type", "setuid");
          event_json.add("uid", final_event->body.setuid_enter.uid);
          event_json.add("gid", final_event->body.setuid_enter.gid);
          event_json.add("comm", final_event->body.setuid_enter.comm);
          event_json.add("arg_uid", final_event->body.setuid_enter.arg_uid);
        } else {
          event_json.add("type", "unknown");
        }
        auto status_json_to_string = event_json.toString(event_str);
        if (status_json_to_string.ok()) {
          osquery::events::dispatchSerializedEvent(event_str);
        } else {
          LOG(ERROR) << "Event serialisation failed: "
                     << status_json_to_string.what();
        }
      }
    }
  }
  return Success{};
}

class SyscallTracingRannable : public ::osquery::InternalRunnable {
 public:
  explicit SyscallTracingRannable()
      : ::osquery::InternalRunnable("SyscallTracingRannable") {}

  void start() override {
    auto ret = runSyscallTracing();
    if (ret.isError()) {
      LOG(ERROR) << "Experimental syscall tracing failed: "
                 << ret.getError().getMessage();
    }
  }

  void stop() override {}
};

} // namespace

namespace impl {

void runSyscallTracingService() {
  Dispatcher::addService(std::make_shared<SyscallTracingRannable>());
}

} // namespace impl
} // namespace events
} // namespace osquery
