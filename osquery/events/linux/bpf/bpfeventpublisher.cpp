/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/events/linux/bpf/bpfeventpublisher.h>
#include <osquery/events/linux/bpf/setrlimit.h>
#include <osquery/events/linux/bpf/systemstatetracker.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/system/time.h>

#include <fcntl.h>
#include <sys/sysinfo.h>

namespace osquery {

namespace {

const std::size_t kEventMapSize{2048};
const std::size_t kMaxNameToHandleAtSize{128U};

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

// Format: syscall, handler, memory pool id
const FunctionTracerAllocatorList kFunctionTracerAllocators = {
    {"fork", &BPFEventPublisher::processForkEvent, 0U},
    {"vfork", &BPFEventPublisher::processVforkEvent, 0U},
    {"clone", &BPFEventPublisher::processCloneEvent, 0U},
    {"close", &BPFEventPublisher::processCloseEvent, 0U},
    {"dup", &BPFEventPublisher::processDupEvent, 0U},
    {"dup2", &BPFEventPublisher::processDup2Event, 0U},
    {"dup3", &BPFEventPublisher::processDup3Event, 0U},
    {"creat", &BPFEventPublisher::processCreatEvent, 1U},
    {"mknod", &BPFEventPublisher::processMknodatEvent, 1U},
    {"mknodat", &BPFEventPublisher::processMknodatEvent, 1U},
    {"name_to_handle_at", &BPFEventPublisher::processNameToHandleAtEvent, 1U},
    {"open_by_handle_at", &BPFEventPublisher::processOpenByHandleAtEvent, 1U},
    {"open", &BPFEventPublisher::processOpenEvent, 2U},
    {"openat", &BPFEventPublisher::processOpenatEvent, 2U},
    {"openat2", &BPFEventPublisher::processOpenat2Event, 1U},
    {"execve", &BPFEventPublisher::processExecveEvent, 3U},
    {"execveat", &BPFEventPublisher::processExecveatEvent, 3U},
    {"socket", &BPFEventPublisher::processSocketEvent, 4U},
    {"fcntl", &BPFEventPublisher::processFcntlEvent, 4U},
    {"connect", &BPFEventPublisher::processConnectEvent, 4U},
    {"accept", &BPFEventPublisher::processAcceptEvent, 4U},
    {"accept4", &BPFEventPublisher::processAccept4Event, 4U},
    {"bind", &BPFEventPublisher::processBindEvent, 4U},
    {"listen", &BPFEventPublisher::processListenEvent, 4U},
    {"chdir", &BPFEventPublisher::processChdirEvent, 5U},
    {"fchdir", &BPFEventPublisher::processFchdirEvent, 5U}};

} // namespace

FLAG(bool,
     enable_bpf_events,
     false,
     "Enables the bpf_process_events publisher");

FLAG(uint64,
     bpf_perf_event_array_exp,
     10ULL,
     "Size of the perf event array as a power of 2");

FLAG(uint64,
     bpf_buffer_storage_size,
     512ULL,
     "How many slots each buffer storage should have");

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
      tob::ebpf::PerfEventArray::create(FLAGS_bpf_perf_event_array_exp);

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
      auto buffer_storage_exp = tob::ebpfpub::IBufferStorage::create(
          FLAGS_bpf_buffer_storage_size, 4096);

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

  tob::ebpfpub::IPerfEventReader::ErrorCounters error_counters{};
  auto last_error_counters_report = getUnixTime();

  while (!isEnding()) {
    d->perf_event_reader->exec(
        std::chrono::seconds(1U),

        [&](const tob::ebpfpub::IFunctionTracer::EventList& event_list,
            const tob::ebpfpub::IPerfEventReader::ErrorCounters&
                new_error_counters) {
          error_counters.invalid_event += new_error_counters.invalid_event;
          error_counters.lost_events += new_error_counters.lost_events;

          error_counters.invalid_probe_output +=
              new_error_counters.invalid_probe_output;

          error_counters.invalid_event_data +=
              new_error_counters.invalid_event_data;

          for (auto& event : event_list) {
            auto rel_timestamp = event.header.timestamp;
            d->event_queue.insert({rel_timestamp, std::move(event)});
          }
        });

    auto current_time = getUnixTime();
    if (last_error_counters_report + 5U < current_time) {
      if (error_counters.invalid_probe_output != 0U) {
        VLOG(1) << "Invalid BPF probe output counter: "
                << error_counters.invalid_probe_output;
      }

      if (error_counters.invalid_event != 0U) {
        VLOG(1) << "Invalid BPF event types counter: "
                << error_counters.invalid_event;
      }

      if (error_counters.invalid_event_data != 0U) {
        VLOG(1) << "Invalid BPF event data counter: "
                << error_counters.invalid_event_data;
      }

      if (error_counters.lost_events != 0U) {
        VLOG(1) << "Lost BPF events counter: " << error_counters.lost_events;
      }

      error_counters = {};
      last_error_counters_report = current_time;
    }

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
        VLOG(1) << "Unhandled event received in BPFEventPublisher: "
                << event.identifier;
        continue;
      }

      const auto& event_handler = event_handler_it->second;
      if (!event_handler(state, event)) {
        VLOG(1) << "BPFEventPublisher failed to process event from tracer #"
                << event.identifier;
        ++invalid_event_count;
      }
    }

    if (invalid_event_count != 0U) {
      LOG(ERROR) << "BPFEventPublisher has encountered " << invalid_event_count
                 << " malformed events";
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

  // The syscall will return a negative errno code if something
  // didn't work
  auto newfd = static_cast<int>(event.header.exit_code);
  if (newfd < 0) {
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
  // The syscall will return a negative errno code if something
  // didn't work
  auto exit_code = static_cast<int>(event.header.exit_code);
  if (exit_code < 0) {
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
  // The syscall will return a negative errno code if something
  // didn't work
  auto exit_code = static_cast<int>(event.header.exit_code);
  if (exit_code < 0) {
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

bool BPFEventPublisher::processCreatEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  // The syscall will return a negative errno code if something
  // didn't work
  auto newfd = static_cast<int>(event.header.exit_code);
  if (newfd < 0) {
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

bool BPFEventPublisher::processMknodatEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  // The syscall will return a negative errno code if something
  // didn't work
  auto newfd = static_cast<int>(event.header.exit_code);
  if (newfd < 0) {
    return true;
  }

  std::uint64_t mode{};
  if (!getEventMapValue(mode, event.in_field_map, "mode")) {
    return false;
  }

  const auto kModeMask = S_IFREG | S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK;
  if ((mode & kModeMask) == 0) {
    mode |= S_IFREG;
  }

  const auto kDiscardedModeMask = S_IFCHR | S_IFBLK;
  if ((mode & kDiscardedModeMask) != 0) {
    return true;
  }

  int dirfd{AT_FDCWD};
  if (event.in_field_map.count("dirfd")) {
    std::uint64_t dirfd_value{};
    if (!getEventMapValue(dirfd_value, event.in_field_map, "dirfd")) {
      return false;
    }

    dirfd = static_cast<int>(dirfd_value);
  }

  std::string pathname;
  if (!getEventMapValue(pathname, event.in_field_map, "filename")) {
    return false;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);
  const int kEmptyFlags{};

  return state.openFile(process_id, dirfd, newfd, pathname, kEmptyFlags);
}

bool BPFEventPublisher::processNameToHandleAtEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  // The syscall will return 0 when it succeeds
  if (event.header.exit_code != 0) {
    return true;
  }

  std::uint64_t dfd{};
  if (!getEventMapValue(dfd, event.in_field_map, "dfd")) {
    return false;
  }

  std::string name;
  if (!getEventMapValue(name, event.out_field_map, "name")) {
    return false;
  }

  std::vector<std::uint8_t> handle;
  if (!getEventMapValue(handle, event.out_field_map, "handle")) {
    return false;
  }

  std::uint64_t mnt_id{};
  if (!getEventMapValue(mnt_id, event.out_field_map, "mnt_id")) {
    return false;
  }

  std::uint64_t flag{};
  if (!getEventMapValue(mnt_id, event.in_field_map, "flag")) {
    return false;
  }

  // Validate the structure size; we at least need 6 bytes for the
  // header
  if (handle.size() < 8U) {
    return true;
  }

  std::uint32_t handle_size{};
  std::memcpy(&handle_size, handle.data(), sizeof(handle_size));

  int handle_type{};
  std::memcpy(&handle_type, handle.data() + 4U, sizeof(handle_type));

  // Limit the size this data so we don't track too much
  // memory
  if (handle_size > kMaxNameToHandleAtSize ||
      handle_size + 8U >= handle.size()) {
    VLOG(1) << "The file_handle struct passed to name_to_handle_at is too big. "
               "Failing this event";

    return false;
  }

  std::vector<std::uint8_t> f_handle;
  f_handle.resize(handle_size);
  std::memcpy(f_handle.data(), handle.data() + 8U, f_handle.size());

  state.nameToHandleAt(dfd, name, handle_type, f_handle, mnt_id, flag);
  return true;
}

bool BPFEventPublisher::processOpenByHandleAtEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  // The syscall will return a negative errno code if something
  // didn't work
  auto newfd = static_cast<int>(event.header.exit_code);
  if (newfd < 0) {
    return true;
  }

  std::uint64_t mountdirfd{};
  if (!getEventMapValue(mountdirfd, event.in_field_map, "mountdirfd")) {
    return false;
  }

  std::vector<std::uint8_t> handle{};
  if (!getEventMapValue(handle, event.in_field_map, "handle")) {
    return false;
  }

  std::uint32_t handle_size{};
  std::memcpy(&handle_size, handle.data(), sizeof(handle_size));

  int handle_type{};
  std::memcpy(&handle_type, handle.data() + 4U, sizeof(handle_type));

  // Limit the size this data so we don't track too much
  // memory
  if (handle_size > kMaxNameToHandleAtSize ||
      handle_size + 8U >= handle.size()) {
    VLOG(1) << "The file_handle struct passed to name_to_handle_at is too big. "
               "Failing this event";

    return false;
  }

  std::vector<std::uint8_t> handle_data;
  handle_data.resize(handle_size);
  std::memcpy(handle_data.data(), handle.data() + 8U, handle_data.size());

  auto process_id = static_cast<pid_t>(event.header.process_id);
  return state.openByHandleAt(
      process_id, mountdirfd, handle_type, handle_data, newfd);
}

bool BPFEventPublisher::processOpenEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  // The syscall will return a negative errno code if something
  // didn't work
  auto newfd = static_cast<int>(event.header.exit_code);
  if (newfd < 0) {
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
  // The syscall will return a negative errno code if something
  // didn't work
  auto newfd = static_cast<int>(event.header.exit_code);
  if (newfd < 0) {
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

bool BPFEventPublisher::processOpenat2Event(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  // The syscall will return a negative errno code if something
  // didn't work
  auto newfd = static_cast<int>(event.header.exit_code);
  if (newfd < 0) {
    return true;
  }

  std::uint64_t dirfd;
  if (!getEventMapValue(dirfd, event.in_field_map, "dfd")) {
    return false;
  }

  std::string filename;
  if (!getEventMapValue(filename, event.out_field_map, "filename")) {
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

bool BPFEventPublisher::processSocketEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  // The syscall will return a negative errno code if something
  // didn't work
  if (static_cast<int>(event.header.exit_code) < 0) {
    return true;
  }

  int fd = static_cast<int>(event.header.exit_code);

  std::uint64_t domain{};
  if (!getEventMapValue(domain, event.in_field_map, "family")) {
    return false;
  }

  std::uint64_t type{};
  if (!getEventMapValue(type, event.in_field_map, "type")) {
    return false;
  }

  std::uint64_t protocol{};
  if (!getEventMapValue(protocol, event.in_field_map, "protocol")) {
    return false;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);
  return state.createSocket(process_id, domain, type, protocol, fd);
}

bool BPFEventPublisher::processFcntlEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  // The syscall will return a negative errno code if something
  // didn't work
  auto new_fd = static_cast<int>(event.header.exit_code);
  if (new_fd < 0) {
    return true;
  }

  std::uint64_t cmd{};
  if (!getEventMapValue(cmd, event.in_field_map, "cmd")) {
    return false;
  }

  if (cmd != F_DUPFD && cmd != F_DUPFD_CLOEXEC) {
    return true;
  }

  std::uint64_t fd{};
  if (!getEventMapValue(fd, event.in_field_map, "fd")) {
    return false;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);

  // Ignore whether the operation has succeeded or not
  auto close_on_exec = (cmd == F_DUPFD_CLOEXEC);
  auto old_fd = static_cast<int>(fd);

  auto status =
      state.duplicateHandle(process_id, old_fd, new_fd, close_on_exec);

  static_cast<void>(status);
  return true;
}

bool BPFEventPublisher::processConnectEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  // Do not check for the exit code; this could be a non-blocking socket
  // that causes the syscall to always return -1
  std::uint64_t fd{};
  if (!getEventMapValue(fd, event.in_field_map, "fd")) {
    return false;
  }

  tob::ebpfpub::IFunctionTracer::Event::Field::Buffer uservaddr;
  if (!getEventMapValue(uservaddr, event.in_field_map, "uservaddr")) {
    return false;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);
  return state.connect(
      event.header, process_id, static_cast<int>(fd), uservaddr);
}

bool BPFEventPublisher::processAcceptEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  // The syscall will return a negative errno code if something
  // didn't work
  int newfd = static_cast<int>(event.header.exit_code);
  if (newfd < 0) {
    return true;
  }

  std::uint64_t fd{};
  if (!getEventMapValue(fd, event.in_field_map, "fd")) {
    return false;
  }

  tob::ebpfpub::IFunctionTracer::Event::Field::Buffer upeer_sockaddr;
  if (!getEventMapValue(
          upeer_sockaddr, event.out_field_map, "upeer_sockaddr")) {
    return false;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);
  auto status = state.accept(
      event.header, process_id, static_cast<int>(fd), upeer_sockaddr, newfd, 0);

  static_cast<void>(status);
  return true;
}

bool BPFEventPublisher::processAccept4Event(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  // The syscall will return a negative errno code if something
  // didn't work
  int newfd = static_cast<int>(event.header.exit_code);
  if (newfd < 0) {
    return true;
  }

  std::uint64_t fd{};
  if (!getEventMapValue(fd, event.in_field_map, "fd")) {
    return false;
  }

  tob::ebpfpub::IFunctionTracer::Event::Field::Buffer upeer_sockaddr;
  if (!getEventMapValue(
          upeer_sockaddr, event.out_field_map, "upeer_sockaddr")) {
    return false;
  }

  std::uint64_t flags{};
  if (!getEventMapValue(flags, event.in_field_map, "flags")) {
    return false;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);
  auto status = state.accept(event.header,
                             process_id,
                             static_cast<int>(fd),
                             upeer_sockaddr,
                             newfd,
                             static_cast<int>(flags));

  static_cast<void>(status);
  return true;
}

bool BPFEventPublisher::processBindEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  if (event.header.exit_code != 0) {
    return true;
  }

  std::uint64_t fd{};
  if (!getEventMapValue(fd, event.in_field_map, "fd")) {
    return false;
  }

  tob::ebpfpub::IFunctionTracer::Event::Field::Buffer uservaddr;
  if (!getEventMapValue(uservaddr, event.in_field_map, "umyaddr")) {
    return false;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);
  return state.bind(event.header, process_id, static_cast<int>(fd), uservaddr);
}

bool BPFEventPublisher::processListenEvent(
    ISystemStateTracker& state,
    const tob::ebpfpub::IFunctionTracer::Event& event) {
  if (event.header.exit_code != 0) {
    return true;
  }

  std::uint64_t fd{};
  if (!getEventMapValue(fd, event.in_field_map, "fd")) {
    return false;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);
  return state.listen(event.header, process_id, static_cast<int>(fd));
}
} // namespace osquery
