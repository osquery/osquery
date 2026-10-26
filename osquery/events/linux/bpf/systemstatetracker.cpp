/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iomanip>
#include <iostream>
#include <sstream>

#include <osquery/events/linux/bpf/systemstatetracker.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/status/status.h>
#include <osquery/utils/system/time.h>

#include <linux/fcntl.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

namespace osquery {

namespace {

const std::size_t kMaxFileHandleEntryCount{512U};
const std::uint64_t kExpirationTime{180U};
const std::size_t kEventsBeforeExpiration{10000U};
}

struct SystemStateTracker::PrivateData final {
  Context context;
  IProcessContextFactory::Ref process_context_factory;
  std::uint64_t last_expiration{};
  std::size_t event_count_since_expiration{};
};

SystemStateTracker::Ref SystemStateTracker::create() {
  IProcessContextFactory::Ref process_context_factory;
  auto status = IProcessContextFactory::create(process_context_factory);
  if (!status) {
    throw status;
  }

  return create(std::move(process_context_factory));
}

SystemStateTracker::Ref SystemStateTracker::create(
    IProcessContextFactory::Ref process_context_factory) {
  try {
    return SystemStateTracker::Ref(
        new SystemStateTracker(std::move(process_context_factory)));

  } catch (const Status& status) {
    LOG(ERROR) << "Failed to create the state tracker: " << status.getMessage();
    return nullptr;

  } catch (const std::bad_alloc&) {
    return nullptr;
  }
}

SystemStateTracker::~SystemStateTracker() {}

Status SystemStateTracker::restart() {
  if (!d->process_context_factory->captureAllProcesses(
          d->context.process_map)) {
    return Status::failure("Failed to scan the procfs folder");
  }

  return Status::success();
}

bool SystemStateTracker::createProcess(
    const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
    pid_t process_id,
    pid_t child_process_id) {
  return createProcess(d->context,
                       *d->process_context_factory.get(),
                       event_header,
                       process_id,
                       child_process_id);
}

bool SystemStateTracker::executeBinary(
    const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
    pid_t process_id,
    int dirfd,
    int flags,
    const std::string& binary_path,
    const tob::ebpfpub::IFunctionTracer::Event::Field::Argv& argv) {
  return executeBinary(d->context,
                       *d->process_context_factory.get(),
                       event_header,
                       process_id,
                       dirfd,
                       flags,
                       binary_path,
                       argv);
}

bool SystemStateTracker::setWorkingDirectory(pid_t process_id, int dirfd) {
  return setWorkingDirectory(
      d->context, *d->process_context_factory.get(), process_id, dirfd);
}

bool SystemStateTracker::setWorkingDirectory(pid_t process_id,
                                             const std::string& path) {
  return setWorkingDirectory(
      d->context, *d->process_context_factory.get(), process_id, path);
}

bool SystemStateTracker::openFile(pid_t process_id,
                                  int dirfd,
                                  int newfd,
                                  const std::string& path,
                                  int flags) {
  return openFile(d->context,
                  *d->process_context_factory.get(),
                  process_id,
                  dirfd,
                  newfd,
                  path,
                  flags);
}

bool SystemStateTracker::duplicateHandle(pid_t process_id,
                                         int oldfd,
                                         int newfd,
                                         bool close_on_exec) {
  return duplicateHandle(d->context, process_id, oldfd, newfd, close_on_exec);
}

bool SystemStateTracker::closeHandle(pid_t process_id, int fd) {
  return closeHandle(
      d->context, *d->process_context_factory.get(), process_id, fd);
}

bool SystemStateTracker::createSocket(
    pid_t process_id, int domain, int type, int protocol, int fd) {
  return createSocket(d->context,
                      *d->process_context_factory.get(),
                      process_id,
                      domain,
                      type,
                      protocol,
                      fd);
}

bool SystemStateTracker::bind(
    const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
    pid_t process_id,
    int fd,
    const std::vector<std::uint8_t>& sockaddr) {
  return bind(d->context,
              *d->process_context_factory.get(),
              event_header,
              process_id,
              fd,
              sockaddr);
}

bool SystemStateTracker::listen(
    const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
    pid_t process_id,
    int fd) {
  return listen(d->context,
                *d->process_context_factory.get(),
                event_header,
                process_id,
                fd);
}

bool SystemStateTracker::connect(
    const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
    pid_t process_id,
    int fd,
    const std::vector<std::uint8_t>& sockaddr) {
  return connect(d->context,
                 *d->process_context_factory.get(),
                 event_header,
                 process_id,
                 fd,
                 sockaddr);
}

bool SystemStateTracker::accept(
    const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
    pid_t process_id,
    int fd,
    const std::vector<std::uint8_t>& sockaddr,
    int newfd,
    int flags) {
  return accept(d->context,
                *d->process_context_factory.get(),
                event_header,
                process_id,
                fd,
                sockaddr,
                newfd,
                flags);
}

void SystemStateTracker::nameToHandleAt(int dfd,
                                        const std::string& name,
                                        int handle_type,
                                        const std::vector<std::uint8_t>& handle,
                                        int mnt_id,
                                        int flag) {
  static std::size_t handles_saved{0U};

  saveFileHandle(d->context, dfd, name, handle_type, handle, mnt_id, flag);
  ++handles_saved;

  if (handles_saved >= 32U) {
    handles_saved = 0U;

    expireFileHandleEntries(d->context, kMaxFileHandleEntryCount);
  }
}

bool SystemStateTracker::openByHandleAt(pid_t process_id,
                                        int mountdirfd,
                                        int handle_type,
                                        const std::vector<std::uint8_t>& handle,
                                        int newfd) {
  return openByHandleAt(d->context,
                        *d->process_context_factory.get(),
                        process_id,
                        mountdirfd,
                        handle_type,
                        handle,
                        newfd);
}

SystemStateTracker::EventList SystemStateTracker::eventList() {
  auto event_list = std::move(d->context.event_list);
  d->context.event_list = {};

  d->event_count_since_expiration += event_list.size();

  auto current_time = getUnixTime();
  if (d->last_expiration + kExpirationTime < current_time ||
      d->event_count_since_expiration >= kEventsBeforeExpiration) {
    IFilesystem::Ref fs;
    auto status = IFilesystem::create(fs);
    if (status.ok()) {
      status = expireProcessContexts(d->context, *fs.get());
      if (!status.ok()) {
        LOG(ERROR) << "BPF system state tracker cleanup error: "
                   << status.getMessage();
      }

    } else {
      LOG(ERROR) << "BPF system state tracker cleanup error: "
                 << status.getMessage();
    }

    d->last_expiration = current_time;
    d->event_count_since_expiration = 0;
  }

  return event_list;
}

SystemStateTracker::SystemStateTracker(
    IProcessContextFactory::Ref process_context_factory)
    : d(new PrivateData) {
  d->last_expiration = getUnixTime();
  d->process_context_factory = std::move(process_context_factory);

  auto status = restart();
  if (!status.ok()) {
    throw status;
  }
}

ProcessContext& SystemStateTracker::getProcessContext(
    Context& context,
    IProcessContextFactory& process_context_factory,
    pid_t process_id) {
  auto process_it = context.process_map.find(process_id);
  if (process_it == context.process_map.end()) {
    ProcessContext process_context;
    if (process_context_factory.captureSingleProcess(process_context,
                                                     process_id)) {
      VLOG(1) << "Created new process context from procfs for pid "
              << process_id << " some fields may be not accurate";
    } else {
      process_context = {};
      VLOG(1) << "Created empty process context for pid " << process_id
              << ". Fields will show up empty";
    }

    auto status =
        context.process_map.insert({process_id, std::move(process_context)});

    process_it = status.first;
  }

  return process_it->second;
}

Status SystemStateTracker::expireProcessContexts(Context& context,
                                                 IFilesystem& fs) {
  tob::utils::UniqueFd procfs_root;
  if (!fs.open(procfs_root, "/proc", O_DIRECTORY)) {
    return Status::failure("Failed to open the procfs root: /proc");
  }

  bool return_error{false};
  for (auto process_map_it = context.process_map.begin();
       process_map_it != context.process_map.end();) {
    auto process_id = std::to_string(process_map_it->first);

    bool exists{false};
    if (!fs.fileExists(exists, procfs_root.get(), process_id.c_str())) {
      return_error = true;
    }

    if (!exists) {
      process_map_it = context.process_map.erase(process_map_it);
    } else {
      ++process_map_it;
    }
  }

  if (return_error) {
    return Status::failure(
        "Failed to access one or more entries in the procfs directory");
  }

  return Status::success();
}

bool SystemStateTracker::createProcess(
    Context& context,
    IProcessContextFactory& process_context_factory,
    const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
    pid_t process_id,
    pid_t child_process_id) {
  ProcessContext child_process_context =
      getProcessContext(context, process_context_factory, process_id);

  child_process_context.parent_process_id = process_id;

  Event event;
  event.type = Event::Type::Fork;
  event.parent_process_id = child_process_context.parent_process_id;
  event.binary_path = child_process_context.binary_path;
  event.cwd = child_process_context.cwd;

  // The BPF header is emitted from the parent process; save it
  // and update it with the child process identifier
  event.bpf_header = event_header;
  event.bpf_header.exit_code = 0;
  event.bpf_header.process_id = event.bpf_header.thread_id = child_process_id;

  context.event_list.push_back(std::move(event));

  context.process_map.insert(
      {child_process_id, std::move(child_process_context)});

  return true;
}

bool SystemStateTracker::executeBinary(
    Context& context,
    IProcessContextFactory& process_context_factory,
    const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
    pid_t process_id,
    int dirfd,
    int flags,
    const std::string& binary_path,
    const tob::ebpfpub::IFunctionTracer::Event::Field::Argv& argv) {
  auto& process_context =
      getProcessContext(context, process_context_factory, process_id);

  auto execute_dirfd = (flags & AT_EMPTY_PATH) != 0;
  auto execute_path = !binary_path.empty();

  if (execute_dirfd == execute_path) {
    return false;
  }

  if (binary_path.empty()) {
    std::string root_path;

    auto fd_info_it = process_context.fd_map.find(dirfd);
    if (fd_info_it == process_context.fd_map.end()) {
      return false;
    }

    auto fd_info = fd_info_it->second;
    if (!std::holds_alternative<ProcessContext::FileDescriptor::FileData>(
            fd_info.data)) {
      return false;
    }

    const auto& file_data =
        std::get<ProcessContext::FileDescriptor::FileData>(fd_info.data);

    process_context.binary_path = file_data.path;

  } else if (binary_path.front() == '/') {
    process_context.binary_path = binary_path;

  } else if (dirfd == AT_FDCWD) {
    process_context.binary_path = process_context.cwd + '/' + binary_path;

  } else {
    std::string root_path;

    auto fd_info_it = process_context.fd_map.find(dirfd);
    if (fd_info_it == process_context.fd_map.end()) {
      return false;
    }

    auto fd_info = fd_info_it->second;
    if (!std::holds_alternative<ProcessContext::FileDescriptor::FileData>(
            fd_info.data)) {
      return false;
    }

    const auto& file_data =
        std::get<ProcessContext::FileDescriptor::FileData>(fd_info.data);
    root_path = file_data.path;

    process_context.binary_path = root_path + '/' + binary_path;
  }

  process_context.argv = argv;

  for (auto fd_it = process_context.fd_map.begin();
       fd_it != process_context.fd_map.end();) {
    const auto& fd_info = fd_it->second;
    if (fd_info.close_on_exec) {
      fd_it = process_context.fd_map.erase(fd_it);
    } else {
      ++fd_it;
    }
  }

  Event event;
  event.type = Event::Type::Exec;
  event.parent_process_id = process_context.parent_process_id;
  event.binary_path = process_context.binary_path;
  event.cwd = process_context.cwd;
  event.bpf_header = event_header;

  Event::ExecData data;
  data.argv = argv;
  event.data = std::move(data);

  context.event_list.push_back(std::move(event));
  return true;
}

bool SystemStateTracker::setWorkingDirectory(
    Context& context,
    IProcessContextFactory& process_context_factory,
    pid_t process_id,
    int dirfd) {
  auto& process_context =
      getProcessContext(context, process_context_factory, process_id);

  auto fd_info_it = process_context.fd_map.find(dirfd);
  if (fd_info_it == process_context.fd_map.end()) {
    return false;
  }

  auto fd_info = fd_info_it->second;
  if (!std::holds_alternative<ProcessContext::FileDescriptor::FileData>(
          fd_info.data)) {
    return false;
  }

  const auto& file_data =
      std::get<ProcessContext::FileDescriptor::FileData>(fd_info.data);

  process_context.cwd = file_data.path;
  return true;
}

bool SystemStateTracker::setWorkingDirectory(
    Context& context,
    IProcessContextFactory& process_context_factory,
    pid_t process_id,
    const std::string& path) {
  auto& process_context =
      getProcessContext(context, process_context_factory, process_id);

  if (path.front() == '/') {
    process_context.cwd = path;

  } else {
    if (process_context.cwd.back() != '/') {
      process_context.cwd += '/';
    }

    process_context.cwd += path;
  }

  return true;
}

bool SystemStateTracker::openFile(
    Context& context,
    IProcessContextFactory& process_context_factory,
    pid_t process_id,
    int dirfd,
    int newfd,
    const std::string& path,
    int flags) {

  auto& process_context =
      getProcessContext(context, process_context_factory, process_id);

  std::string absolute_path;
  if (!path.empty() && path.front() == '/') {
    absolute_path = path;

  } else if (dirfd == AT_FDCWD) {
    if (path.empty()) {
      return false;
    }

    absolute_path = process_context.cwd;
    if (absolute_path.back() != '/') {
      absolute_path += '/';
    }

    absolute_path += path;

  } else {
    auto fd_info_it = process_context.fd_map.find(dirfd);
    if (fd_info_it == process_context.fd_map.end()) {
      return false;
    }

    auto fd_info = fd_info_it->second;
    if (!std::holds_alternative<ProcessContext::FileDescriptor::FileData>(
            fd_info.data)) {
      return false;
    }

    const auto& file_data =
        std::get<ProcessContext::FileDescriptor::FileData>(fd_info.data);

    absolute_path = file_data.path;

    if ((flags & AT_EMPTY_PATH) == 0) {
      if (absolute_path.back() != '/') {
        absolute_path += '/';
      }

      absolute_path += path;
    }
  }

  ProcessContext::FileDescriptor fd_info;
  fd_info.close_on_exec = ((flags & O_CLOEXEC) != 0);

  ProcessContext::FileDescriptor::FileData file_data;
  file_data.path = std::move(absolute_path);
  fd_info.data = std::move(file_data);

  process_context.fd_map.insert({newfd, std::move(fd_info)});
  return true;
}

bool SystemStateTracker::duplicateHandle(Context& context,
                                         pid_t process_id,
                                         int oldfd,
                                         int newfd,
                                         bool close_on_exec) {
  auto process_context_it = context.process_map.find(process_id);
  if (process_context_it == context.process_map.end()) {
    return false;
  }

  auto& process_context = process_context_it->second;
  auto fd_info_it = process_context.fd_map.find(oldfd);
  if (fd_info_it == process_context.fd_map.end()) {
    return false;
  }

  auto new_fd_info = fd_info_it->second;
  new_fd_info.close_on_exec = close_on_exec;
  process_context.fd_map.insert({newfd, std::move(new_fd_info)});

  return true;
}

bool SystemStateTracker::closeHandle(
    Context& context,
    IProcessContextFactory& process_context_factory,
    pid_t process_id,
    int fd) {
  if (context.process_map.find(process_id) == context.process_map.end()) {
    return true;
  }

  auto& process_context =
      getProcessContext(context, process_context_factory, process_id);

  auto fd_info_it = process_context.fd_map.find(fd);
  if (fd_info_it == process_context.fd_map.end()) {
    return false;
  }

  process_context.fd_map.erase(fd_info_it);
  return true;
}

bool SystemStateTracker::createSocket(
    Context& context,
    IProcessContextFactory& process_context_factory,
    pid_t process_id,
    int domain,
    int type,
    int protocol,
    int fd) {
  auto& process_context =
      getProcessContext(context, process_context_factory, process_id);

  ProcessContext::FileDescriptor fd_info;
  fd_info.close_on_exec = false;

  ProcessContext::FileDescriptor::SocketData socket_data;
  socket_data.opt_domain = domain;
  socket_data.opt_type = type;
  socket_data.opt_protocol = protocol;
  fd_info.data = std::move(socket_data);

  process_context.fd_map.insert({fd, std::move(fd_info)});
  return true;
}

bool SystemStateTracker::bind(
    Context& context,
    IProcessContextFactory& process_context_factory,
    const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
    pid_t process_id,
    int fd,
    const std::vector<std::uint8_t>& sockaddr) {
  auto& process_context =
      getProcessContext(context, process_context_factory, process_id);

  // If we dont have a file descriptor, create one right now. We may have
  // to figure out what's in the sockaddr structure
  auto fd_info_it = process_context.fd_map.find(fd);
  if (fd_info_it == process_context.fd_map.end()) {
    ProcessContext::FileDescriptor fd_info;
    fd_info.close_on_exec = false;
    fd_info.data = ProcessContext::FileDescriptor::SocketData{};

    auto insert_status =
        process_context.fd_map.insert({fd, std::move(fd_info)});

    fd_info_it = insert_status.first;
  }

  // Reset the file descriptor type if it's not a socket
  auto& fd_info = fd_info_it->second;
  if (!std::holds_alternative<ProcessContext::FileDescriptor::SocketData>(
          fd_info.data)) {
    fd_info.data = ProcessContext::FileDescriptor::SocketData{};
  }

  auto& socket_address =
      std::get<ProcessContext::FileDescriptor::SocketData>(fd_info.data);

  if (!parseSocketAddress(socket_address, sockaddr, true)) {
    return false;
  }

  Event event;
  event.type = Event::Type::Bind;
  event.parent_process_id = process_context.parent_process_id;
  event.binary_path = process_context.binary_path;
  event.cwd = process_context.cwd;
  event.bpf_header = event_header;

  Event::SocketData data;
  data.fd = fd;

  if (socket_address.opt_domain.has_value()) {
    data.domain = socket_address.opt_domain.value();
  }

  if (socket_address.opt_type.has_value()) {
    data.type = socket_address.opt_type.value();
  }

  if (socket_address.opt_protocol.has_value()) {
    data.protocol = socket_address.opt_protocol.value();
  }

  if (socket_address.opt_local_address.has_value()) {
    data.local_address = socket_address.opt_local_address.value();
  }

  if (socket_address.opt_local_port.has_value()) {
    data.local_port = socket_address.opt_local_port.value();
  }

  if (socket_address.opt_remote_address.has_value()) {
    data.remote_address = socket_address.opt_remote_address.value();
  }

  if (socket_address.opt_remote_port.has_value()) {
    data.remote_port = socket_address.opt_remote_port.value();
  }

  event.data = std::move(data);
  context.event_list.push_back(std::move(event));
  return true;
}

bool SystemStateTracker::listen(
    Context& context,
    IProcessContextFactory& process_context_factory,
    const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
    pid_t process_id,
    int fd) {
  Event::SocketData data;
  data.fd = fd;

  auto& process_context =
      getProcessContext(context, process_context_factory, process_id);

  auto fd_info_it = process_context.fd_map.find(fd);
  if (fd_info_it != process_context.fd_map.end()) {
    auto& fd_info = fd_info_it->second;

    if (std::holds_alternative<ProcessContext::FileDescriptor::SocketData>(
            fd_info.data)) {
      auto& socket_address =
          std::get<ProcessContext::FileDescriptor::SocketData>(fd_info.data);

      if (socket_address.opt_domain.has_value()) {
        data.domain = socket_address.opt_domain.value();
      }

      if (socket_address.opt_type.has_value()) {
        data.type = socket_address.opt_type.value();
      }

      if (socket_address.opt_protocol.has_value()) {
        data.protocol = socket_address.opt_protocol.value();
      }

      if (socket_address.opt_local_address.has_value()) {
        data.local_address = socket_address.opt_local_address.value();
      }

      if (socket_address.opt_local_port.has_value()) {
        data.local_port = socket_address.opt_local_port.value();
      }

      if (socket_address.opt_remote_address.has_value()) {
        data.remote_address = socket_address.opt_remote_address.value();
      }

      if (socket_address.opt_remote_port.has_value()) {
        data.remote_port = socket_address.opt_remote_port.value();
      }
    }
  }

  Event event;
  event.type = Event::Type::Listen;
  event.parent_process_id = process_context.parent_process_id;
  event.binary_path = process_context.binary_path;
  event.cwd = process_context.cwd;
  event.bpf_header = event_header;
  event.data = std::move(data);

  context.event_list.push_back(std::move(event));
  return true;
}

bool SystemStateTracker::connect(
    Context& context,
    IProcessContextFactory& process_context_factory,
    const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
    pid_t process_id,
    int fd,
    const std::vector<std::uint8_t>& sockaddr) {
  auto& process_context =
      getProcessContext(context, process_context_factory, process_id);

  // If we dont have a file descriptor, create one right now. We may have
  // to figure out what's in the sockaddr structure
  auto fd_info_it = process_context.fd_map.find(fd);
  if (fd_info_it == process_context.fd_map.end()) {
    ProcessContext::FileDescriptor fd_info;
    fd_info.close_on_exec = false;
    fd_info.data = ProcessContext::FileDescriptor::SocketData{};

    auto insert_status =
        process_context.fd_map.insert({fd, std::move(fd_info)});

    fd_info_it = insert_status.first;
  }

  // Reset the file descriptor type if it's not a socket
  auto& fd_info = fd_info_it->second;
  if (!std::holds_alternative<ProcessContext::FileDescriptor::SocketData>(
          fd_info.data)) {
    fd_info.data = ProcessContext::FileDescriptor::SocketData{};
  }

  auto& socket_address =
      std::get<ProcessContext::FileDescriptor::SocketData>(fd_info.data);

  if (!parseSocketAddress(socket_address, sockaddr, false)) {
    return false;
  }

  Event event;
  event.type = Event::Type::Connect;
  event.parent_process_id = process_context.parent_process_id;
  event.binary_path = process_context.binary_path;
  event.cwd = process_context.cwd;
  event.bpf_header = event_header;

  Event::SocketData data;
  data.fd = fd;

  if (socket_address.opt_domain.has_value()) {
    data.domain = socket_address.opt_domain.value();
  }

  if (socket_address.opt_type.has_value()) {
    data.type = socket_address.opt_type.value();
  }

  if (socket_address.opt_protocol.has_value()) {
    data.protocol = socket_address.opt_protocol.value();
  }

  if (socket_address.opt_local_address.has_value()) {
    data.local_address = socket_address.opt_local_address.value();
  }

  if (socket_address.opt_local_port.has_value()) {
    data.local_port = socket_address.opt_local_port.value();
  }

  if (socket_address.opt_remote_address.has_value()) {
    data.remote_address = socket_address.opt_remote_address.value();
  }

  if (socket_address.opt_remote_port.has_value()) {
    data.remote_port = socket_address.opt_remote_port.value();
  }

  event.data = std::move(data);
  context.event_list.push_back(std::move(event));
  return true;
}

bool SystemStateTracker::accept(
    Context& context,
    IProcessContextFactory& process_context_factory,
    const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
    pid_t process_id,
    int fd,
    const std::vector<std::uint8_t>& sockaddr,
    int newfd,
    int flags) {
  auto& process_context =
      getProcessContext(context, process_context_factory, process_id);

  // If we dont have a file descriptor, create one right now. We may have
  // to figure out what's in the sockaddr structure
  auto parent_fd_info_it = process_context.fd_map.find(fd);
  if (parent_fd_info_it == process_context.fd_map.end()) {
    ProcessContext::FileDescriptor fd_info;
    fd_info.close_on_exec = false;
    fd_info.data = ProcessContext::FileDescriptor::SocketData{};

    auto insert_status =
        process_context.fd_map.insert({fd, std::move(fd_info)});

    parent_fd_info_it = insert_status.first;
  }

  // Reset the parent file descriptor type if it's not a socket
  auto& parent_fd_info = parent_fd_info_it->second;
  if (!std::holds_alternative<ProcessContext::FileDescriptor::SocketData>(
          parent_fd_info.data)) {
    parent_fd_info.data = ProcessContext::FileDescriptor::SocketData{};
  }

  // Create the new socket, based on the parent one
  auto new_fd_info = parent_fd_info;
  new_fd_info.close_on_exec = ((flags & SOCK_CLOEXEC) != 0);

  auto& socket_address =
      std::get<ProcessContext::FileDescriptor::SocketData>(new_fd_info.data);

  socket_address.opt_remote_address = {};
  socket_address.opt_remote_port = {};

  if (!parseSocketAddress(socket_address, sockaddr, false)) {
    return false;
  }

  process_context.fd_map.insert({newfd, new_fd_info});

  Event event;
  event.type = Event::Type::Accept;
  event.parent_process_id = process_context.parent_process_id;
  event.binary_path = process_context.binary_path;
  event.cwd = process_context.cwd;
  event.bpf_header = event_header;

  Event::SocketData data;
  data.fd = newfd;

  if (socket_address.opt_domain.has_value()) {
    data.domain = socket_address.opt_domain.value();
  }

  if (socket_address.opt_type.has_value()) {
    data.type = socket_address.opt_type.value();
  }

  if (socket_address.opt_protocol.has_value()) {
    data.protocol = socket_address.opt_protocol.value();
  }

  if (socket_address.opt_local_address.has_value()) {
    data.local_address = socket_address.opt_local_address.value();
  }

  if (socket_address.opt_local_port.has_value()) {
    data.local_port = socket_address.opt_local_port.value();
  }

  if (socket_address.opt_remote_address.has_value()) {
    data.remote_address = socket_address.opt_remote_address.value();
  }

  if (socket_address.opt_remote_port.has_value()) {
    data.remote_port = socket_address.opt_remote_port.value();
  }

  event.data = std::move(data);
  context.event_list.push_back(std::move(event));
  return true;
}

bool SystemStateTracker::openByHandleAt(
    Context& context,
    IProcessContextFactory& process_context_factory,
    pid_t process_id,
    int mountdirfd,
    int handle_type,
    const std::vector<std::uint8_t>& handle,
    int newfd) {
  // Locate the right file_handle struct
  auto index = createFileHandleIndex(handle_type, handle);

  auto file_handle_it = context.file_handle_struct_map.find(index);
  if (file_handle_it == context.file_handle_struct_map.end()) {
    return false;
  }

  const auto& file_handle = file_handle_it->second;

  // Attempt to use the file_handle struct to locate the file
  auto& process_context =
      getProcessContext(context, process_context_factory, process_id);

  std::string absolute_path;

  if (!file_handle.name.empty()) {
    if (file_handle.name.front() == '/') {
      absolute_path = file_handle.name;

    } else {
      std::string base_path;

      if (file_handle.dfd == AT_FDCWD) {
        base_path = process_context.cwd;

      } else {
        auto fd_info_it = process_context.fd_map.find(file_handle.dfd);
        if (fd_info_it == process_context.fd_map.end()) {
          return false;
        }

        const auto& fd_info = fd_info_it->second;
        if (!std::holds_alternative<ProcessContext::FileDescriptor::FileData>(
                fd_info.data)) {
          return false;
        }

        const auto& file_data =
            std::get<ProcessContext::FileDescriptor::FileData>(fd_info.data);

        base_path = file_data.path;
      }

      absolute_path = base_path + '/' + file_handle.name;
    }

  } else if ((file_handle.flags & AT_EMPTY_PATH) != 0) {
    auto fd_info_it = process_context.fd_map.find(file_handle.dfd);
    if (fd_info_it == process_context.fd_map.end()) {
      return false;
    }

    const auto& fd_info = fd_info_it->second;
    if (!std::holds_alternative<ProcessContext::FileDescriptor::FileData>(
            fd_info.data)) {
      return false;
    }

    const auto& file_data =
        std::get<ProcessContext::FileDescriptor::FileData>(fd_info.data);

    absolute_path = file_data.path;

  } else {
    return false;
  }

  ProcessContext::FileDescriptor fd_info{};
  ProcessContext::FileDescriptor::FileData file_data{};
  file_data.path = std::move(absolute_path);
  fd_info.data = std::move(file_data);

  process_context.fd_map.insert({newfd, std::move(fd_info)});
  return true;
}

bool SystemStateTracker::parseUnixSockaddr(
    std::string& path, const std::vector<std::uint8_t>& sockaddr) {
  path = {};

  std::uint16_t family{};
  std::memcpy(&family, sockaddr.data(), sizeof(family));

  if (family != AF_UNSPEC && family != AF_UNIX) {
    return false;
  }

  auto size = std::min(sizeof(sockaddr_un), sockaddr.size());

  sockaddr_un addr{};
  std::memcpy(&addr, sockaddr.data(), size);
  path = addr.sun_path;

  return true;
}

bool SystemStateTracker::parseInetSockaddr(
    std::string& address,
    std::uint16_t& port,
    const std::vector<std::uint8_t>& sockaddr) {
  address = {};
  port = 0U;

  std::uint16_t family{};
  std::memcpy(&family, sockaddr.data(), sizeof(family));

  if (family != AF_UNSPEC && family != AF_INET) {
    return false;
  }

  auto size = std::min(sizeof(sockaddr_in), sockaddr.size());

  sockaddr_in addr{};
  std::memcpy(&addr, sockaddr.data(), size);

  port = static_cast<std::uint16_t>(ntohs(addr.sin_port));

  std::uint8_t components[4];
  std::memcpy(components, &addr.sin_addr.s_addr, sizeof(components));

  address = std::to_string(components[0]) + '.';
  address += std::to_string(components[1]) + '.';
  address += std::to_string(components[2]) + '.';
  address += std::to_string(components[3]);

  return true;
}

bool SystemStateTracker::parseInet6Sockaddr(
    std::string& address,
    std::uint16_t& port,
    const std::vector<std::uint8_t>& sockaddr) {
  address = {};
  port = 0U;

  // We already know we have at least 2 bytes
  std::uint16_t family{};
  std::memcpy(&family, sockaddr.data(), sizeof(family));

  if (family != AF_UNSPEC && family != AF_INET6) {
    return false;
  }

  // We may have received less bytes than the full structure size, so
  // make sure we copy only what we have
  auto size = std::min(sizeof(sockaddr_in6), sockaddr.size());

  sockaddr_in6 addr{};
  std::memcpy(&addr, sockaddr.data(), size);

  port = static_cast<std::uint16_t>(ntohs(addr.sin6_port));

  // Convert the address bytes from a byte array to a u16 array.
  // While we are doing the conversion, also look for the largest
  // sequence of zeroes that we'll later compress with `::`
  struct ZeroSequence final {
    std::size_t start_index;
    std::size_t end_index;
  };

  bool inside_zero_seq{false};
  ZeroSequence current_zero_seq;

  std::vector<std::uint16_t> part_list;
  ZeroSequence biggest_zero_sequence{};

  bool should_collapse_zero_seq{false};
  auto L_updateMaxZeroSequence = [&biggest_zero_sequence,
                                  &should_collapse_zero_seq](
                                     const ZeroSequence& seq) {
    if ((seq.end_index - seq.start_index) >
        (biggest_zero_sequence.end_index - biggest_zero_sequence.start_index)) {
      biggest_zero_sequence = seq;
      should_collapse_zero_seq = true;
    }
  };

  for (std::size_t i = 0U; i < 16; i += 2) {
    std::uint16_t value = addr.sin6_addr.s6_addr[i + 1];
    value |= static_cast<std::uint16_t>(addr.sin6_addr.s6_addr[i]) << 8;

    if (inside_zero_seq) {
      if (value != 0) {
        current_zero_seq.end_index = part_list.size() - 1;
        L_updateMaxZeroSequence(current_zero_seq);

        current_zero_seq = {};
        inside_zero_seq = false;
      }

    } else if (value == 0) {
      inside_zero_seq = true;
      current_zero_seq.start_index = part_list.size();
    }

    part_list.push_back(value);
  }

  if (inside_zero_seq) {
    current_zero_seq.end_index = 7;
    L_updateMaxZeroSequence(current_zero_seq);
  }

  // Transform each u16 to string, and also handle compression
  std::stringstream buffer;
  buffer << std::hex;

  for (std::size_t i = 0U; i < 8;) {
    if (should_collapse_zero_seq && i >= biggest_zero_sequence.start_index &&
        i < biggest_zero_sequence.end_index) {
      buffer << ":";

      if (i == 0) {
        buffer << ":";
      }

      i = biggest_zero_sequence.end_index + 1;

    } else {
      buffer << part_list.at(i);

      if (i + 1 < 8) {
        buffer << ":";
      }

      ++i;
    }
  }

  address = buffer.str();
  return true;
}

bool SystemStateTracker::parseNetlinkSockaddr(
    std::string& address,
    std::uint16_t& port,
    const std::vector<std::uint8_t>& sockaddr) {
  address = {};
  port = 0U;

  std::uint16_t family{};
  std::memcpy(&family, sockaddr.data(), sizeof(family));

  if (family != AF_UNSPEC && family != AF_NETLINK) {
    return false;
  }

  auto size = std::min(sizeof(sockaddr_in), sockaddr.size());

  sockaddr_nl addr{};
  std::memcpy(&addr, sockaddr.data(), size);

  address = std::to_string(addr.nl_groups);
  port = static_cast<std::uint16_t>(addr.nl_pid);

  return true;
}

bool SystemStateTracker::parseSocketAddress(
    ProcessContext::FileDescriptor::SocketData& socket_data,
    const std::vector<std::uint8_t>& sockaddr,
    bool local) {
  if (local) {
    socket_data.opt_local_address = {};
    socket_data.opt_local_port = {};
  } else {
    socket_data.opt_remote_address = {};
    socket_data.opt_remote_port = {};
  }

  if (sockaddr.size() < 2U) {
    return false;
  }

  std::uint16_t family{};
  std::memcpy(&family, sockaddr.data(), sizeof(family));

  if (family == AF_UNSPEC && socket_data.opt_domain.has_value()) {
    family = socket_data.opt_domain.value();
  }

  if (family == AF_UNSPEC) {
    if (sockaddr.size() == sizeof(sockaddr_in)) {
      family = AF_INET;

    } else if (sockaddr.size() == sizeof(sockaddr_in6)) {
      family = AF_INET6;

    } else if (sockaddr.size() == sizeof(sockaddr_nl)) {
      family = AF_NETLINK;

    } else if (sockaddr.size() == sizeof(sockaddr_un)) {
      family = AF_UNIX;
    }
  }

  std::string address;
  std::uint16_t port{};

  bool succeeded{false};
  if (!succeeded && (family == AF_UNSPEC || family == AF_INET)) {
    succeeded = parseInetSockaddr(address, port, sockaddr);
  }

  if (!succeeded && (family == AF_UNSPEC || family == AF_INET6)) {
    succeeded = parseInet6Sockaddr(address, port, sockaddr);
  }

  if (!succeeded && (family == AF_UNSPEC || family == AF_NETLINK)) {
    succeeded = parseNetlinkSockaddr(address, port, sockaddr);
  }

  if (!succeeded && (family == AF_UNSPEC || family == AF_UNIX)) {
    succeeded = parseUnixSockaddr(address, sockaddr);
  }

  if (succeeded) {
    if (local) {
      socket_data.opt_local_address = address;
      socket_data.opt_local_port = port;

    } else {
      socket_data.opt_remote_address = address;
      socket_data.opt_remote_port = port;
    }
  }

  return succeeded;
}

std::string SystemStateTracker::createFileHandleIndex(
    int handle_type, const std::vector<std::uint8_t>& handle) {
  std::stringstream buffer;

  buffer << std::setfill('0') << std::setw(8) << std::hex << handle_type << "_";

  for (const auto& b : handle) {
    buffer << std::setfill('0') << std::setw(2) << static_cast<int>(b);
  }

  return buffer.str();
}

void SystemStateTracker::saveFileHandle(Context& context,
                                        int dfd,
                                        const std::string& name,
                                        int handle_type,
                                        const std::vector<std::uint8_t>& handle,
                                        int mnt_id,
                                        int flag) {
  FileHandleStruct file_handle;
  file_handle.dfd = dfd;
  file_handle.name = name;
  file_handle.flags = flag;

  auto index = createFileHandleIndex(handle_type, handle);
  if (context.file_handle_struct_map.count(index) > 0) {
    return;
  }

  context.file_handle_struct_map.insert({index, std::move(file_handle)});
  context.file_handle_struct_index.push_back(std::move(index));
}

void SystemStateTracker::expireFileHandleEntries(Context& context,
                                                 std::size_t max_size) {
  if (max_size == 0U || context.file_handle_struct_index.size() < max_size) {
    return;
  }

  auto elements_to_remove = context.file_handle_struct_index.size() - max_size;
  if (elements_to_remove == 0U) {
    return;
  }

  auto start_range = context.file_handle_struct_index.begin();
  auto end_range = std::next(start_range, elements_to_remove);

  for (auto it = start_range; it != end_range; ++it) {
    const auto& index = *it;
    context.file_handle_struct_map.erase(index);
  }

  context.file_handle_struct_index.erase(start_range, end_range);
}

SystemStateTracker::Context SystemStateTracker::getContextCopy() const {
  return d->context;
}

} // namespace osquery
