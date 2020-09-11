/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/events/linux/bpf/systemstatetracker.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/status/status.h>

#include <fcntl.h>

namespace osquery {
struct SystemStateTracker::PrivateData final {
  Context context;
};

SystemStateTracker::Ref SystemStateTracker::create() {
  try {
    return SystemStateTracker::Ref(new SystemStateTracker());

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
  return createProcess(d->context, event_header, process_id, child_process_id);
}

bool SystemStateTracker::executeBinary(
    const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
    pid_t process_id,
    int dirfd,
    int flags,
    const std::string& binary_path,
    const tob::ebpfpub::IFunctionTracer::Event::Field::Argv& argv) {
  return executeBinary(
      d->context, event_header, process_id, dirfd, flags, binary_path, argv);
}

bool SystemStateTracker::setWorkingDirectory(pid_t process_id, int dirfd) {
  return setWorkingDirectory(d->context, process_id, dirfd);
}

bool SystemStateTracker::setWorkingDirectory(pid_t process_id,
                                             const std::string& path) {
  return setWorkingDirectory(d->context, process_id, path);
}

bool SystemStateTracker::openFile(pid_t process_id,
                                  int dirfd,
                                  int newfd,
                                  const std::string& path,
                                  int flags) {
  return openFile(d->context, process_id, dirfd, newfd, path, flags);
}

bool SystemStateTracker::duplicateHandle(pid_t process_id,
                                         int oldfd,
                                         int newfd,
                                         bool close_on_exec) {
  return duplicateHandle(d->context, process_id, oldfd, newfd, close_on_exec);
}

bool SystemStateTracker::closeHandle(pid_t process_id, int fd) {
  return closeHandle(d->context, process_id, fd);
}

SystemStateTracker::SystemStateTracker() : d(new PrivateData) {
  if (!createProcessContextMap(d->context.process_map)) {
    throw Status::failure("Failed to scan the procfs folder");
  }
}

ProcessContext& SystemStateTracker::getProcessContext(Context& context,
                                                      pid_t process_id) {
  auto process_it = context.process_map.find(process_id);
  if (process_it == context.process_map.end()) {
    ProcessContext process_context;
    if (!createProcessContext(process_context, process_id)) {
      process_context = {};
    }

    auto status =
        context.process_map.insert({process_id, std::move(process_context)});

    process_it = status.first;
  }

  return process_it->second;
}

bool SystemStateTracker::createProcess(
    Context& context,
    const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
    pid_t process_id,
    pid_t child_process_id) {
  ProcessContext child_process_context = getProcessContext(context, process_id);
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
    const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
    pid_t process_id,
    int dirfd,
    int flags,
    const std::string& binary_path,
    const tob::ebpfpub::IFunctionTracer::Event::Field::Argv& argv) {
  auto& process_context = getProcessContext(context, process_id);

  if (binary_path.front() == '/') {
    process_context.binary_path = binary_path;

  } else if (dirfd == -1 || dirfd == AT_FDCWD) {
    process_context.binary_path = process_context.cwd + "/" + binary_path;

  } else {
    std::string root_path;

    auto fd_info_it = process_context.fd_map.find(dirfd);
    if (fd_info_it == process_context.fd_map.end()) {
      return false;
    }

    auto fd_info = fd_info_it->second;
    root_path = fd_info.path;

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

bool SystemStateTracker::setWorkingDirectory(Context& context,
                                             pid_t process_id,
                                             int dirfd) {
  auto& process_context = getProcessContext(context, process_id);

  auto fd_info_it = process_context.fd_map.find(dirfd);
  if (fd_info_it == process_context.fd_map.end()) {
    return false;
  }

  auto fd_info = fd_info_it->second;
  process_context.cwd = fd_info.path;

  return true;
}

bool SystemStateTracker::setWorkingDirectory(Context& context,
                                             pid_t process_id,
                                             const std::string& path) {
  auto& process_context = getProcessContext(context, process_id);

  if (path.front() == '/') {
    process_context.cwd = path;
  } else {
    process_context.cwd += "/" + path;
  }

  return true;
}

bool SystemStateTracker::openFile(Context& context,
                                  pid_t process_id,
                                  int dirfd,
                                  int newfd,
                                  const std::string& path,
                                  int flags) {
  if (path.empty()) {
    return false;
  }

  auto& process_context = getProcessContext(context, process_id);

  std::string absolute_path;
  if (path.front() == '/') {
    absolute_path = path;

  } else if (dirfd == -1 || dirfd == AT_FDCWD) {
    absolute_path = process_context.cwd + "/" + path;

  } else {
    auto fd_info_it = process_context.fd_map.find(dirfd);
    if (fd_info_it == process_context.fd_map.end()) {
      return false;
    }

    auto fd_info = fd_info_it->second;
    absolute_path = fd_info.path + "/" + path;
  }

  ProcessContext::FileDescriptor fd_info;
  fd_info.close_on_exec = ((flags & O_CLOEXEC) != 0);
  fd_info.path = absolute_path;

  process_context.fd_map.insert({newfd, std::move(fd_info)});
  return true;
}

bool SystemStateTracker::duplicateHandle(Context& context,
                                         pid_t process_id,
                                         int oldfd,
                                         int newfd,
                                         bool close_on_exec) {
  auto& process_context = getProcessContext(context, process_id);

  auto fd_info_it = process_context.fd_map.find(oldfd);
  if (fd_info_it == process_context.fd_map.end()) {
    return false;
  }

  auto new_fd_info = fd_info_it->second;
  new_fd_info.close_on_exec = close_on_exec;
  process_context.fd_map.insert({newfd, std::move(new_fd_info)});

  return true;
}

bool SystemStateTracker::closeHandle(Context& context,
                                     pid_t process_id,
                                     int fd) {
  auto& process_context = getProcessContext(context, process_id);

  auto fd_info_it = process_context.fd_map.find(fd);
  if (fd_info_it == process_context.fd_map.end()) {
    return false;
  }

  process_context.fd_map.erase(fd_info_it);
  return true;
}

SystemStateTracker::EventList SystemStateTracker::eventList() {
  auto event_list = std::move(d->context.event_list);
  d->context.event_list = {};

  return event_list;
}
} // namespace osquery
