/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/core/flags.h>
#include <osquery/events/linux/bpf/bpfeventpublisher.h>
#include <osquery/events/linux/bpf/setrlimit.h>
#include <osquery/events/linux/bpf/systemstatetracker.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

#include <fcntl.h>
#include <sys/sysinfo.h>

namespace osquery {
namespace {
const std::size_t kPerfEventArraySize{12U};
const std::size_t kBufferStorageSize{4096U};
const std::size_t kEventMapSize{2048};

using EventHandler = bool (*)(ISystemStateTracker& state,
                              const tob::ebpfpub::IFunctionTracer::Event&);

using EventHandlerMap = std::unordered_map<std::uint64_t, EventHandler>;

using BufferStorageMap =
    std::unordered_map<std::uint8_t, tob::ebpfpub::IBufferStorage::Ref>;

struct FunctionTracerAllocator final {
  std::string syscall_name;
  EventHandler event_handler;
  std::uint8_t buffer_storage_pool{0U};
};

using FunctionTracerAllocatorList = std::vector<FunctionTracerAllocator>;

extern const FunctionTracerAllocatorList kFunctionTracerAllocators;
} // namespace

FLAG(bool,
     enable_bpf_events,
     false,
     "Enables the bpf_process_events publisher");

REGISTER(BPFEventPublisher, "event_publisher", "BPFEventPublisher");

struct BPFEventPublisher::PrivateData final {
  bool initialized{false};

  tob::ebpf::PerfEventArray::Ref perf_event_array;
  tob::ebpfpub::IPerfEventReader::Ref perf_event_reader;
  BufferStorageMap buffer_storage_map;
  EventHandlerMap event_handler_map;

  std::map<std::uint64_t, tob::ebpfpub::IFunctionTracer::Event> event_queue;
  ISystemStateTracker::Ref system_state_tracker;
};

Status BPFEventPublisher::setUp() {
  if (!FLAGS_enable_bpf_events) {
    return Status::failure("Publisher disabled via configuration");
  }

  auto status = configureBPFMemoryLimits();
  if (!status.ok()) {
    return status;
  }

  auto perf_event_array_exp =
      tob::ebpf::PerfEventArray::create(kPerfEventArraySize);

  if (!perf_event_array_exp.succeeded()) {
    throw std::runtime_error("Failed to create the perf event array: " +
                             perf_event_array_exp.error().message());
  }

  d->perf_event_array = perf_event_array_exp.takeValue();

  auto perf_event_reader_exp =
      tob::ebpfpub::IPerfEventReader::create(*d->perf_event_array.get());

  if (!perf_event_reader_exp.succeeded()) {
    throw std::runtime_error("Failed to create the perf event reader: " +
                             perf_event_reader_exp.error().message());
  }

  d->perf_event_reader = perf_event_reader_exp.takeValue();

  for (const auto& tracer_allocator : kFunctionTracerAllocators) {
    auto buffer_storage_it =
        d->buffer_storage_map.find(tracer_allocator.buffer_storage_pool);

    if (buffer_storage_it == d->buffer_storage_map.end()) {
      auto buffer_storage_exp =
          tob::ebpfpub::IBufferStorage::create(kBufferStorageSize, 4096);

      if (!buffer_storage_exp.succeeded()) {
        throw buffer_storage_exp.error();
      }

      auto buffer_storage = buffer_storage_exp.takeValue();
      auto insert_status = d->buffer_storage_map.insert(
          {tracer_allocator.buffer_storage_pool, std::move(buffer_storage)});

      buffer_storage_it = insert_status.first;
    }

    auto& buffer_storage = *buffer_storage_it->second.get();

    auto function_tracer_exp =
        tob::ebpfpub::IFunctionTracer::createFromSyscallTracepoint(
            tracer_allocator.syscall_name,
            buffer_storage,
            *d->perf_event_array.get(),
            kEventMapSize);

    if (!function_tracer_exp.succeeded()) {
      std::stringstream verbose_message;
      verbose_message << "Failed to load the BPF probe for syscall "
                      << tracer_allocator.syscall_name << ": "
                      << function_tracer_exp.error().message();

      if (tracer_allocator.syscall_name == "openat2") {
        verbose_message << ". This syscall may not be available on this "
                           "system, continuining despite the error";
      }

      VLOG(1) << verbose_message.str();
      if (tracer_allocator.syscall_name == "openat2") {
        continue;
      }

      return Status::failure("Failed to create the function tracer: " +
                             function_tracer_exp.error().message());
    }

    auto function_tracer = function_tracer_exp.takeValue();
    auto event_id = function_tracer->eventIdentifier();

    VLOG(1) << "Initialized BPF probe for syscall "
            << tracer_allocator.syscall_name << " (" << event_id << ")";

    d->event_handler_map[event_id] = tracer_allocator.event_handler;
    d->perf_event_reader->insert(std::move(function_tracer));
  }

  d->system_state_tracker = SystemStateTracker::create();
  if (!d->system_state_tracker) {
    return Status::failure("Failed to create the system state tracker object");
  }

  d->initialized = true;
  return Status::success();
}

void BPFEventPublisher::configure() {
  if (!FLAGS_enable_bpf_events) {
    return;
  }
}

void BPFEventPublisher::tearDown() {
  if (!FLAGS_enable_bpf_events) {
    return;
  }

  if (!d->initialized) {
    return;
  }
}

Status BPFEventPublisher::run() {
  if (!FLAGS_enable_bpf_events) {
    return Status::failure("Publisher disabled via configuration");
  }

  if (!d->initialized) {
    return Status::failure(
        "Halting the publisher since initialization has failed");
  }

  while (!isEnding()) {
    d->perf_event_reader->exec(
        std::chrono::seconds(1U),

        [&](const tob::ebpfpub::IFunctionTracer::EventList& event_list,
            const tob::ebpfpub::IPerfEventReader::ErrorCounters&
                error_counters) {
          if (error_counters.invalid_probe_output != 0U) {
            VLOG(1) << "invalid_probe_output: "
                    << error_counters.invalid_probe_output << "\n";
          }

          if (error_counters.invalid_event != 0U) {
            VLOG(1) << "invalid_event: " << error_counters.invalid_event
                    << "\n";
          }

          if (error_counters.invalid_event_data != 0U) {
            VLOG(1) << "invalid_event_data: "
                    << error_counters.invalid_event_data << "\n";
          }

          if (error_counters.lost_events != 0U) {
            VLOG(1) << "lost_events: " << error_counters.lost_events << "\n";
          }

          for (auto& event : event_list) {
            auto rel_timestamp = event.header.timestamp;
            d->event_queue.insert({rel_timestamp, std::move(event)});
          }
        });

    std::size_t invalid_event_count = 0U;
    auto& state = *d->system_state_tracker.get();

    struct sysinfo system_info {};
    sysinfo(&system_info);

    for (auto event_it = d->event_queue.begin();
         event_it != d->event_queue.end();) {
      const auto& rel_timestamp = event_it->first / 1000000000ULL;
      if (system_info.uptime - rel_timestamp < 5ULL) {
        ++event_it;
        continue;
      }

      auto event = std::move(event_it->second);
      event_it = d->event_queue.erase(event_it);

      auto event_handler_it = d->event_handler_map.find(event.identifier);
      if (event_handler_it == d->event_handler_map.end()) {
        VLOG(1) << "Unhandled event received: " << event.identifier << "\n";
        continue;
      }

      const auto& event_handler = event_handler_it->second;
      if (!event_handler(state, event)) {
        VLOG(1) << "Error processing event from tracer #" << event.identifier;
        ++invalid_event_count;
      }
    }

    if (invalid_event_count != 0U) {
      LOG(ERROR) << invalid_event_count << " malformed events received";
    }

    auto event_list = state.eventList();
    if (!event_list.empty()) {
      auto event_context = createEventContext();
      event_context->event_list = std::move(event_list);

      fire(event_context);
    }
  }

  return Status::success();
}

BPFEventPublisher::BPFEventPublisher() : d(new PrivateData) {}

BPFEventPublisher::~BPFEventPublisher() {
  tearDown();
}

bool BPFEventPublisher::processForkEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  auto child_process_id = static_cast<pid_t>(event.header.exit_code);
  if (child_process_id == -1) {
    return true;
  }

  return state.createProcess(
      event.header, event.header.process_id, child_process_id);
}

bool BPFEventPublisher::processVforkEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  return processForkEvent(state, event);
}

bool BPFEventPublisher::processCloneEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  std::uint64_t clone_flags{};
  if (!getEventMapValue(clone_flags, event.in_field_map, "clone_flags")) {
    return false;
  }

  if ((clone_flags & CLONE_THREAD) != 0) {
    return true;
  }

  return processForkEvent(state, event);
}

bool BPFEventPublisher::processExecveEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  std::string binary_path;
  if (!getEventMapValue(binary_path, event.in_field_map, "filename")) {
    return false;
  }

  tob::ebpfpub::IFunctionTracer::Event::Field::Argv argv;
  if (!getEventMapValue(argv, event.in_field_map, "argv")) {
    return false;
  }

  auto process_id = event.header.process_id;

  static constexpr int kNoDirfd{AT_FDCWD};
  static constexpr int kNoExecveFlags{0};

  return state.executeBinary(
      event.header, process_id, kNoDirfd, kNoExecveFlags, binary_path, argv);
}

bool BPFEventPublisher::processExecveatEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  std::string binary_path;
  if (!getEventMapValue(binary_path, event.in_field_map, "filename")) {
    return false;
  }

  tob::ebpfpub::IFunctionTracer::Event::Field::Argv argv;
  if (!getEventMapValue(argv, event.in_field_map, "argv")) {
    return false;
  }

  std::uint64_t flags{};
  if (!getEventMapValue(flags, event.in_field_map, "flags")) {
    return false;
  }

  std::uint64_t dirfd{};
  if (!getEventMapValue(dirfd, event.in_field_map, "fd")) {
    return false;
  }

  auto process_id = event.header.process_id;

  return state.executeBinary(event.header,
                             process_id,
                             static_cast<int>(dirfd),
                             static_cast<int>(flags),
                             binary_path,
                             argv);
}

bool BPFEventPublisher::processCloseEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  std::uint64_t fd_value{};
  if (!getEventMapValue(fd_value, event.in_field_map, "fd")) {
    return false;
  }

  auto fd = static_cast<int>(fd_value);
  if (fd == -1) {
    return true;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);

  // Ignore whether the operation has succeeded or not
  auto status = state.closeHandle(process_id, fd);
  static_cast<void>(status);

  return true;
}

bool BPFEventPublisher::processDupEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  std::uint64_t fildes_value{};
  if (!getEventMapValue(fildes_value, event.in_field_map, "fildes")) {
    return false;
  }

  auto fildes = static_cast<int>(fildes_value);
  if (fildes == -1) {
    return true;
  }

  auto newfd = static_cast<int>(event.header.exit_code);
  if (newfd == -1) {
    return true;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);
  static constexpr int kCloseOnExec{false};

  // Ignore whether the operation has succeeded or not
  auto status = state.duplicateHandle(process_id, fildes, newfd, kCloseOnExec);
  static_cast<void>(status);

  return true;
}

bool BPFEventPublisher::processDup2Event(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  auto exit_code = static_cast<int>(event.header.exit_code);
  if (exit_code == -1) {
    return true;
  }

  std::uint64_t fd_value{};
  if (!getEventMapValue(fd_value, event.in_field_map, "oldfd")) {
    return false;
  }

  auto oldfd = static_cast<int>(fd_value);

  if (!getEventMapValue(fd_value, event.in_field_map, "newfd")) {
    return false;
  }

  auto newfd = static_cast<int>(fd_value);
  if (newfd == oldfd) {
    return true;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);
  static constexpr int kCloseOnExec{false};

  // Ignore whether the operation has succeeded or not
  auto status = state.duplicateHandle(process_id, oldfd, newfd, kCloseOnExec);
  static_cast<void>(status);

  return true;
}

bool BPFEventPublisher::processDup3Event(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  auto exit_code = static_cast<int>(event.header.exit_code);
  if (exit_code == -1) {
    return true;
  }

  std::uint64_t fd_value{};
  if (!getEventMapValue(fd_value, event.in_field_map, "oldfd")) {
    return false;
  }

  auto oldfd = static_cast<int>(fd_value);

  if (!getEventMapValue(fd_value, event.in_field_map, "newfd")) {
    return false;
  }

  auto newfd = static_cast<int>(fd_value);
  if (newfd == oldfd) {
    return true;
  }

  std::uint64_t flags{};
  if (!getEventMapValue(flags, event.in_field_map, "flags")) {
    return false;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);
  auto close_on_exec = (flags & O_CLOEXEC) != 0;

  // Ignore whether the operation has succeeded or not
  auto status = state.duplicateHandle(process_id, oldfd, newfd, close_on_exec);
  static_cast<void>(status);

  return true;
}

// clang-format off
[[deprecated("processNameToHandleAtEvent() is not yet implemented")]]
// clang-format on
bool BPFEventPublisher::processNameToHandleAtEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  return true;
}

bool BPFEventPublisher::processCreatEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  auto newfd = static_cast<int>(event.header.exit_code);
  if (newfd == -1) {
    return true;
  }

  std::string path;
  if (!getEventMapValue(path, event.in_field_map, "pathname")) {
    return false;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);
  static constexpr int kNoDirfd{AT_FDCWD};
  static constexpr int kOpenFlags{O_CREAT | O_WRONLY | O_TRUNC};

  return state.openFile(process_id, kNoDirfd, newfd, path, kOpenFlags);
}

bool BPFEventPublisher::processMknodEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  return true;
}

bool BPFEventPublisher::processMknodatEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  return true;
}

bool BPFEventPublisher::processOpenEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  auto newfd = static_cast<int>(event.header.exit_code);
  if (newfd == -1) {
    return true;
  }

  std::uint64_t flags;
  if (!getEventMapValue(flags, event.in_field_map, "flags")) {
    return false;
  }

  std::string filename;
  if (!getEventMapValue(filename, event.in_field_map, "filename")) {
    return false;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);
  static constexpr int kNoDirfd{AT_FDCWD};

  return state.openFile(
      process_id, kNoDirfd, newfd, filename, static_cast<int>(flags));
}

bool BPFEventPublisher::processOpenatEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  auto newfd = static_cast<int>(event.header.exit_code);
  if (newfd == -1) {
    return true;
  }

  std::uint64_t flags;
  if (!getEventMapValue(flags, event.in_field_map, "flags")) {
    return false;
  }

  std::uint64_t dirfd;
  if (!getEventMapValue(dirfd, event.in_field_map, "dfd")) {
    return false;
  }

  // It is possible for the memory page containing the filename string to
  // not be mapped when we start executing our probe. Since BPF can't handle
  // page faults, we would get back an empty string.
  //
  // To work around this issue, this parameter has been switch from IN to OUT
  // in the tracepointserializers.cpp file, so that we capture this when exiting
  // the syscall. This makes sure that the string is readable by the
  // bpf_read_str helper
  std::string filename;
  if (!getEventMapValue(filename, event.out_field_map, "filename")) {
    return false;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);
  return state.openFile(process_id,
                        static_cast<int>(dirfd),
                        newfd,
                        filename,
                        static_cast<int>(flags));
}

// clang-format off
[[deprecated("processOpenat2Event() is not yet implemented")]]
// clang-format on
bool BPFEventPublisher::processOpenat2Event(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  auto newfd = static_cast<int>(event.header.exit_code);
  if (newfd == -1) {
    return true;
  }

  std::uint64_t dirfd;
  if (!getEventMapValue(dirfd, event.in_field_map, "dfd")) {
    return false;
  }

  std::string filename;
  if (!getEventMapValue(filename, event.in_field_map, "filename")) {
    return false;
  }

  tob::ebpfpub::IFunctionTracer::Event::Field::Buffer buffer;
  if (!getEventMapValue(buffer, event.in_field_map, "how")) {
    return false;
  }

  struct open_how {
    std::uint64_t flags;
    std::uint64_t mode;
    std::uint64_t resolve;
  } openat_arguments;

  auto size = std::min(sizeof(openat_arguments), buffer.size());
  std::memcpy(&openat_arguments, buffer.data(), size);

  auto process_id = static_cast<pid_t>(event.header.process_id);
  return state.openFile(process_id,
                        static_cast<int>(dirfd),
                        newfd,
                        filename,
                        static_cast<int>(openat_arguments.flags));
}

// clang-format off
[[deprecated("processOpenByHandleAtEvent() is not yet implemented")]]
// clang-format on
bool BPFEventPublisher::processOpenByHandleAtEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  return true;
}

bool BPFEventPublisher::processChdirEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  if (event.header.exit_code != 0) {
    return true;
  }

  std::string filename;
  if (!getEventMapValue(filename, event.in_field_map, "filename")) {
    return false;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);

  return state.setWorkingDirectory(process_id, filename);
}

bool BPFEventPublisher::processFchdirEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  if (event.header.exit_code != 0) {
    return true;
  }

  std::uint64_t dirfd{};
  if (!getEventMapValue(dirfd, event.in_field_map, "fd")) {
    return false;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);
  return state.setWorkingDirectory(process_id, static_cast<int>(dirfd));
}

// clang-format off
[[deprecated("processSocketEvent() is not yet implemented")]]
// clang-format on
bool BPFEventPublisher::processSocketEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  return true;
}

// clang-format off
[[deprecated("processConnectEvent() is not yet implemented")]]
// clang-format on
bool BPFEventPublisher::processConnectEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  return true;
}

// clang-format off
[[deprecated("processAcceptEvent() is not yet implemented")]]
// clang-format on
bool BPFEventPublisher::processAcceptEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  return true;
}

// clang-format off
[[deprecated("processAccept4Event() is not yet implemented")]]
// clang-format on
bool BPFEventPublisher::processAccept4Event(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  return true;
}

// clang-format off
[[deprecated("processBindEvent() is not yet implemented")]]
// clang-format on
bool BPFEventPublisher::processBindEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  return true;
}

namespace {
// clang-format off
const FunctionTracerAllocatorList kFunctionTracerAllocators = {
  {
    "fork",
    &BPFEventPublisher::processForkEvent,
    0U
  },

  {
    "vfork",
    &BPFEventPublisher::processVforkEvent,
    0U
  },

  {
    "clone",
    &BPFEventPublisher::processCloneEvent,
    0U
  },

  {
    "close",
    &BPFEventPublisher::processCloseEvent,
    0U
  },

  {
    "dup",
    &BPFEventPublisher::processDupEvent,
    0U
  },

  {
    "dup2",
    &BPFEventPublisher::processDup2Event,
    0U
  },

  {
    "dup3",
    &BPFEventPublisher::processDup3Event,
    0U
  },

  /*{
    "name_to_handle_at",
    &BPFEventPublisher::processNameToHandleAtEvent,
    1U
  },*/

  {
    "creat",
    &BPFEventPublisher::processCreatEvent,
    1U
  },

  {
    "mknod",
    &BPFEventPublisher::processMknodEvent,
    1U
  },

  {
    "mknodat",
    &BPFEventPublisher::processMknodatEvent,
    1U
  },

  {
    "open",
    &BPFEventPublisher::processOpenEvent,
    2U
  },

  {
    "openat",
    &BPFEventPublisher::processOpenatEvent,
    2U
  },

  {
    "openat2",
    &BPFEventPublisher::processOpenat2Event,
    1U
  },

  /*{
    "open_by_handle_at",
    &BPFEventPublisher::processOpenByHandleAtEvent,
    1U
  },*/

  {
    "execve",
    &BPFEventPublisher::processExecveEvent,
    3U
  },

  {
    "execveat",
    &BPFEventPublisher::processExecveatEvent,
    3U
  },

  /*{
    "socket",
    &BPFEventPublisher::processSocketEvent,
    4U
  },

  {
    "connect",
    &BPFEventPublisher::processConnectEvent,
    4U
  },

  {
    "accept",
    &BPFEventPublisher::processAcceptEvent,
    4U
  },

  {
    "accept4",
    &BPFEventPublisher::processAccept4Event,
    4U
  },

  {
    "bind",
    &BPFEventPublisher::processBindEvent,
    4U
  },*/

  {
    "chdir",
    &BPFEventPublisher::processChdirEvent,
    5U
  },

  {
    "fchdir",
    &BPFEventPublisher::processFchdirEvent,
    5U
  }
};
// clang-format on
} // namespace
} // namespace osquery
