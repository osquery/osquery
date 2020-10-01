/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <iomanip>
#include <sstream>

#include <osquery/events/linux/bpf/systemstatetracker.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/status/status.h>

#include <linux/fcntl.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

namespace osquery {
struct SystemStateTracker::PrivateData final {
  Context context;
  IProcessContextFactory::Ref process_context_factory;
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
    LOG(ERROR) << status.getMessage();
    return nullptr;

  } catch (const std::bad_alloc&) {
    return nullptr;
  }
}

SystemStateTracker::~SystemStateTracker() {}

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

SystemStateTracker::EventList SystemStateTracker::eventList() {
  auto event_list = std::move(d->context.event_list);
  d->context.event_list = {};

  return event_list;
}

SystemStateTracker::SystemStateTracker(
    IProcessContextFactory::Ref process_context_factory)
    : d(new PrivateData) {
  d->process_context_factory = std::move(process_context_factory);

  if (!d->process_context_factory->captureAllProcesses(
          d->context.process_map)) {
    throw Status::failure("Failed to scan the procfs folder");
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
    process_context.binary_path = process_context.cwd + "/" + binary_path;

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

    process_context.binary_path = root_path + "/" + binary_path;
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
      process_context.cwd += "/";
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
  if (path.empty()) {
    return false;
  }

  auto& process_context =
      getProcessContext(context, process_context_factory, process_id);

  std::string absolute_path;
  if (path.front() == '/') {
    absolute_path = path;

  } else if (dirfd == AT_FDCWD) {
    absolute_path = process_context.cwd;
    if (absolute_path.back() != '/') {
      absolute_path += "/";
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
    if (absolute_path.back() != '/') {
      absolute_path += "/";
    }

    absolute_path += path;
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

  address = std::to_string(components[0]) + ".";
  address += std::to_string(components[1]) + ".";
  address += std::to_string(components[2]) + ".";
  address += std::to_string(components[3]);

  return true;
}

bool SystemStateTracker::parseInet6Sockaddr(
    std::string& address,
    std::uint16_t& port,
    const std::vector<std::uint8_t>& sockaddr) {
  address = {};
  port = 0U;

  std::uint16_t family{};
  std::memcpy(&family, sockaddr.data(), sizeof(family));

  if (family != AF_UNSPEC && family != AF_INET6) {
    return false;
  }

  auto size = std::min(sizeof(sockaddr_in6), sockaddr.size());

  sockaddr_in6 addr{};
  std::memcpy(&addr, sockaddr.data(), size);

  port = static_cast<std::uint16_t>(ntohs(addr.sin6_port));

  std::stringstream buffer;
  for (std::size_t i = 0U; i < 16; ++i) {
    buffer << std::setfill('0') << std::setw(2) << std::hex
           << static_cast<int>(addr.sin6_addr.s6_addr[i]);

    if (i + 1 < sizeof(addr.sin6_addr.s6_addr)) {
      buffer << ":";
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
    VLOG(1)
        << "Invalid sockaddr structure received (less than 2 bytes available)";
    return false;
  }

  std::uint16_t family{};
  std::memcpy(&family, sockaddr.data(), sizeof(family));

  if (family == AF_UNSPEC && socket_data.opt_domain.has_value()) {
    family = socket_data.opt_domain.value();
  }

  std::string address;
  std::uint16_t port{};

  bool succeeded{false};
  if (family == AF_UNSPEC || family == AF_UNIX) {
    succeeded = parseUnixSockaddr(address, sockaddr);

  } else if (!succeeded && (family == AF_UNSPEC || family == AF_INET)) {
    succeeded = parseInetSockaddr(address, port, sockaddr);

  } else if (!succeeded && (family == AF_UNSPEC || family == AF_INET6)) {
    succeeded = parseInet6Sockaddr(address, port, sockaddr);

  } else if (!succeeded && (family == AF_UNSPEC || family == AF_NETLINK)) {
    succeeded = parseNetlinkSockaddr(address, port, sockaddr);
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

SystemStateTracker::Context SystemStateTracker::getContextCopy() const {
  return d->context;
}
} // namespace osquery
