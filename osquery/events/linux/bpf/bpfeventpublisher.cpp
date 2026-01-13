/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/events/linux/bpf/bpferrorstate.h>
#include <osquery/events/linux/bpf/bpfeventpublisher.h>
#include <osquery/events/linux/bpf/serializers.h>
#include <osquery/events/linux/bpf/setrlimit.h>
#include <osquery/events/linux/bpf/systemstatetracker.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/system/time.h>

#include <fcntl.h>
#include <sys/sysinfo.h>

namespace osquery {

HIDDEN_FLAG(uint32,
            bpf_state_tracker_reset_time,
            10,
            "Number of minutes between BPF system state tracker resets");

namespace ebpf = tob::ebpf;

// Placeholder types to replace removed ebpfpub types
struct BPFEvent {
  std::uint64_t identifier{};
  std::string name;
  BPFEventHeader header;
  // field maps removed - ebpfpub dependency
};

using EventHandler = bool (*)(ISystemStateTracker& state, const BPFEvent&);
using EventHandlerMap = std::unordered_map<std::uint64_t, EventHandler>;
using BufferStorageMap = std::unordered_map<std::uint8_t, void*>; // placeholder

struct FunctionTracerAllocator final {
  std::string syscall_name;
  EventHandler event_handler;
  std::uint8_t buffer_storage_pool{0U};
  bool kprobe{false};
};

std::unordered_set<std::string> kOptionalSyscallList{"openat2",

#ifdef __aarch64__
                                                     "fork",
                                                     "vfork",
                                                     "dup2",
                                                     "dup3",
                                                     "creat",
                                                     "mknod",
                                                     "open"
#endif
};

using FunctionTracerAllocatorList = std::vector<FunctionTracerAllocator>;

// ebpfpub removed - function tracer allocators no longer available
const FunctionTracerAllocatorList kFunctionTracerAllocators = {};
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

  ebpf::PerfEventArray::Ref perf_event_array;
  // ebpfpub::IPerfEventReader removed
  BufferStorageMap buffer_storage_map;
  EventHandlerMap event_handler_map;

  std::map<std::uint64_t, BPFEvent> event_queue;
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
      ebpf::PerfEventArray::create(FLAGS_bpf_perf_event_array_exp);

  if (!perf_event_array_exp.succeeded()) {
    const auto& error = perf_event_array_exp.error();

    return Status::failure("Failed to create the perf event array: " +
                           error.message());
  }

  d->perf_event_array = perf_event_array_exp.takeValue();

  // ebpfpub removed - perf event reader and function tracers no longer available

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

  d->perf_event_array.reset();
  // d->perf_event_reader.reset(); // ebpfpub removed
  d->system_state_tracker.reset();

  d->buffer_storage_map.clear();
  d->event_handler_map.clear();
  d->event_queue.clear();

  d->initialized = false;
}

Status BPFEventPublisher::run() {
  if (!FLAGS_enable_bpf_events) {
    return Status::failure("Publisher disabled via configuration");
  }

  if (!d->initialized) {
    return Status::failure(
        "Halting the publisher since initialization has failed");
  }

  BPFErrorState bpf_error_state;

  auto last_error_report = getUnixTime();
  auto last_tracker_restart = getUnixTime();

  while (!isEnding()) {
    auto current_time = getUnixTime();
    if (last_tracker_restart + (FLAGS_bpf_state_tracker_reset_time * 60) <
        current_time) {
      auto status = d->system_state_tracker->restart();
      if (!status.ok()) {
        LOG(ERROR) << "The BPF system state tracker could not be successfully "
                      "restarted: "
                   << status.getMessage();
      } else {
        VLOG(1)
            << "The BPF system state tracker has been successfully restarted";
      }

      last_tracker_restart = current_time;
    }

    // ebpfpub removed - perf event reader no longer available
    // Event processing disabled

    current_time = getUnixTime();
    if (last_error_report + 5U < current_time) {
      reportAndClearBpfErrorState(bpf_error_state);
      last_error_report = current_time;
    }

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
        LOG(ERROR) << "Unhandled event received in BPFEventPublisher: "
                   << event.identifier;
        continue;
      }

      const auto& event_handler = event_handler_it->second;
      if (!event_handler(state, event)) {
        bpf_error_state.errored_tracer_list.insert(event.identifier);
      }
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
    ISystemStateTracker& state, const BPFEvent& event) {
  auto child_process_id = static_cast<pid_t>(event.header.exit_code);
  if (child_process_id == -1) {
    return true;
  }

  return state.createProcess(
      event.header, event.header.process_id, child_process_id);
}

bool BPFEventPublisher::processVforkEvent(
    ISystemStateTracker& state, const BPFEvent& event) {
  return processForkEvent(state, event);
}

bool BPFEventPublisher::processCloneEvent(
    ISystemStateTracker& state, const BPFEvent& event) {
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
    ISystemStateTracker& state, const BPFEvent& event) {
  std::string binary_path;
  if (!getEventMapValue(binary_path, event.in_field_map, "filename")) {
    return false;
  }

  BPFEventArgv argv;
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
    ISystemStateTracker& state, const BPFEvent& event) {
  std::string binary_path;
  if (!getEventMapValue(binary_path, event.in_field_map, "filename")) {
    return false;
  }

  BPFEventArgv argv;
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
    ISystemStateTracker& state, const BPFEvent& event) {
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
    ISystemStateTracker& state, const BPFEvent& event) {
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
    ISystemStateTracker& state, const BPFEvent& event) {
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
    ISystemStateTracker& state, const BPFEvent& event) {
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
    ISystemStateTracker& state, const BPFEvent& event) {
  // The syscall will return a negative errno code if something
  // didn't work
  auto newfd = static_cast<int>(event.header.exit_code);
  if (newfd < 0) {
    return true;
  }

  std::string path;
  if (!getEventMapValue(path, event.out_field_map, "pathname")) {
    return false;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);
  static constexpr int kNoDirfd{AT_FDCWD};
  static constexpr int kOpenFlags{O_CREAT | O_WRONLY | O_TRUNC};

  return state.openFile(process_id, kNoDirfd, newfd, path, kOpenFlags);
}

bool BPFEventPublisher::processMknodatEvent(
    ISystemStateTracker& state, const BPFEvent& event) {
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
  if (!getEventMapValue(pathname, event.out_field_map, "filename")) {
    return false;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);
  const int kEmptyFlags{};

  return state.openFile(process_id, dirfd, newfd, pathname, kEmptyFlags);
}

bool BPFEventPublisher::processNameToHandleAtEvent(
    ISystemStateTracker& state, const BPFEvent& event) {
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
    ISystemStateTracker& state, const BPFEvent& event) {
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
    ISystemStateTracker& state, const BPFEvent& event) {
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
  if (!getEventMapValue(filename, event.out_field_map, "filename")) {
    return false;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);
  static constexpr int kNoDirfd{AT_FDCWD};

  return state.openFile(
      process_id, kNoDirfd, newfd, filename, static_cast<int>(flags));
}

bool BPFEventPublisher::processOpenatEvent(
    ISystemStateTracker& state, const BPFEvent& event) {
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
    ISystemStateTracker& state, const BPFEvent& event) {
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

  std::vector<std::uint8_t> buffer;
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
    ISystemStateTracker& state, const BPFEvent& event) {
  if (event.header.exit_code != 0) {
    return true;
  }

  std::string filename;
  if (!getEventMapValue(filename, event.out_field_map, "filename")) {
    return false;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);
  return state.setWorkingDirectory(process_id, filename);
}

bool BPFEventPublisher::processFchdirEvent(
    ISystemStateTracker& state, const BPFEvent& event) {
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
    ISystemStateTracker& state, const BPFEvent& event) {
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
    ISystemStateTracker& state, const BPFEvent& event) {
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
    ISystemStateTracker& state, const BPFEvent& event) {
  // Do not check for the exit code; this could be a non-blocking socket
  // that causes the syscall to always return -1
  std::uint64_t fd{};
  if (!getEventMapValue(fd, event.in_field_map, "fd")) {
    return false;
  }

  std::vector<std::uint8_t> uservaddr;
  if (!getEventMapValue(uservaddr, event.in_field_map, "uservaddr")) {
    return false;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);
  return state.connect(
      event.header, process_id, static_cast<int>(fd), uservaddr);
}

bool BPFEventPublisher::processAcceptEvent(
    ISystemStateTracker& state, const BPFEvent& event) {
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

  std::vector<std::uint8_t> upeer_sockaddr;
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
    ISystemStateTracker& state, const BPFEvent& event) {
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

  std::vector<std::uint8_t> upeer_sockaddr;
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
    ISystemStateTracker& state, const BPFEvent& event) {
  if (event.header.exit_code != 0) {
    return true;
  }

  std::uint64_t fd{};
  if (!getEventMapValue(fd, event.in_field_map, "fd")) {
    return false;
  }

  std::vector<std::uint8_t> uservaddr;
  if (!getEventMapValue(uservaddr, event.in_field_map, "umyaddr")) {
    return false;
  }

  auto process_id = static_cast<pid_t>(event.header.process_id);
  return state.bind(event.header, process_id, static_cast<int>(fd), uservaddr);
}

bool BPFEventPublisher::processListenEvent(
    ISystemStateTracker& state, const BPFEvent& event) {
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
