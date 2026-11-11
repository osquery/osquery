/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "utils.h"

#include <gtest/gtest.h>

namespace osquery {

void setFileDescriptor(ProcessContext& process_context,
                       int fd,
                       bool close_on_exec,
                       const std::string& path) {
  process_context.fd_map.erase(fd);

  ProcessContext::FileDescriptor fd_info;
  fd_info.close_on_exec = close_on_exec;

  ProcessContext::FileDescriptor::FileData file_data;
  file_data.path = path;
  fd_info.data = std::move(file_data);

  process_context.fd_map.insert({fd, std::move(fd_info)});
}

void setFileDescriptor(ProcessContextMap& process_context_map,
                       pid_t process_id,
                       int fd,
                       bool close_on_exec,
                       const std::string& path) {
  auto process_context_it = process_context_map.find(process_id);
  ASSERT_NE(process_context_it, process_context_map.end());

  auto& process_context = process_context_it->second;
  setFileDescriptor(process_context, fd, close_on_exec, path);
}

void setSocketDescriptor(ProcessContext& process_context,
                         int fd,
                         bool close_on_exec,
                         int domain,
                         int type,
                         int protocol,
                         const std::string& local_address,
                         std::uint16_t local_port,
                         const std::string& remote_address,
                         std::uint16_t remote_port) {
  process_context.fd_map.erase(fd);

  ProcessContext::FileDescriptor fd_info;
  fd_info.close_on_exec = close_on_exec;

  ProcessContext::FileDescriptor::SocketData socket_data;
  socket_data.opt_domain = domain;
  socket_data.opt_type = type;
  socket_data.opt_protocol = protocol;

  socket_data.opt_local_address = local_address;
  socket_data.opt_local_port = local_port;

  socket_data.opt_remote_address = remote_address;
  socket_data.opt_remote_port = remote_port;

  fd_info.data = std::move(socket_data);
  process_context.fd_map.insert({fd, std::move(fd_info)});
}

void setSocketDescriptor(ProcessContextMap& process_context_map,
                         pid_t process_id,
                         int fd,
                         bool close_on_exec,
                         int domain,
                         int type,
                         int protocol,
                         const std::string& local_address,
                         std::uint16_t local_port,
                         const std::string& remote_address,
                         std::uint16_t remote_port) {
  auto process_context_it = process_context_map.find(process_id);
  ASSERT_NE(process_context_it, process_context_map.end());

  auto& process_context = process_context_it->second;
  setSocketDescriptor(process_context,
                      fd,
                      close_on_exec,
                      domain,
                      type,
                      protocol,
                      local_address,
                      local_port,
                      remote_address,
                      remote_port);
}

bool validateFileDescriptor(const ProcessContext& process_context,
                            int fd,
                            bool close_on_exec,
                            const std::string& path) {
  auto fd_it = process_context.fd_map.find(fd);
  if (fd_it == process_context.fd_map.end()) {
    return false;
  }

  const auto& fd_info = fd_it->second;
  if (fd_info.close_on_exec != close_on_exec) {
    return false;
  }

  if (!std::holds_alternative<ProcessContext::FileDescriptor::FileData>(
          fd_info.data)) {
    return false;
  }

  const auto& file_info =
      std::get<ProcessContext::FileDescriptor::FileData>(fd_info.data);
  if (file_info.path != path) {
    return false;
  }

  return true;
}

bool validateFileDescriptor(const ProcessContextMap& process_context_map,
                            pid_t process_id,
                            int fd,
                            bool close_on_exec,
                            const std::string& path) {
  auto process_context_it = process_context_map.find(process_id);
  if (process_context_it == process_context_map.end()) {
    return false;
  }

  const auto& process_context = process_context_it->second;
  return validateFileDescriptor(process_context, fd, close_on_exec, path);
}

bool validateSocketDescriptor(const ProcessContext& process_context,
                              int fd,
                              bool close_on_exec,
                              int domain,
                              int type,
                              int protocol,
                              const std::string& local_address,
                              std::uint16_t local_port,
                              const std::string& remote_address,
                              std::uint16_t remote_port) {
  auto fd_it = process_context.fd_map.find(fd);
  if (fd_it == process_context.fd_map.end()) {
    return false;
  }

  const auto& fd_info = fd_it->second;
  if (fd_info.close_on_exec != close_on_exec) {
    return false;
  }

  if (!std::holds_alternative<ProcessContext::FileDescriptor::SocketData>(
          fd_info.data)) {
    return false;
  }

  const auto& socket_info =
      std::get<ProcessContext::FileDescriptor::SocketData>(fd_info.data);

  if (!socket_info.opt_domain.has_value() || socket_info.opt_type.has_value() ||
      socket_info.opt_protocol.has_value()) {
    return false;
  }

  if (socket_info.opt_domain.value() != domain ||
      socket_info.opt_type.value() != type ||
      socket_info.opt_protocol.value() != protocol) {
    return false;
  }

  if (!socket_info.opt_local_address.has_value() ||
      socket_info.opt_local_address.value() != local_address) {
    return false;
  }

  if (!socket_info.opt_local_port.has_value() ||
      socket_info.opt_local_port.value() != local_port) {
    return false;
  }

  if (!socket_info.opt_remote_address.has_value() ||
      socket_info.opt_remote_address.value() != remote_address) {
    return false;
  }

  if (!socket_info.opt_remote_port.has_value() ||
      socket_info.opt_remote_port.value() != remote_port) {
    return false;
  }

  return true;
}

bool validateSocketDescriptor(const ProcessContextMap& process_context_map,
                              pid_t process_id,
                              int fd,
                              bool close_on_exec,
                              int domain,
                              int type,
                              int protocol,
                              const std::string& local_address,
                              std::uint16_t local_port,
                              const std::string& remote_address,
                              std::uint16_t remote_port) {
  auto process_context_it = process_context_map.find(process_id);
  if (process_context_it == process_context_map.end()) {
    return false;
  }

  const auto& process_context = process_context_it->second;
  return validateSocketDescriptor(process_context,
                                  fd,
                                  close_on_exec,
                                  domain,
                                  type,
                                  protocol,
                                  local_address,
                                  local_port,
                                  remote_address,
                                  remote_port);
}

} // namespace osquery
