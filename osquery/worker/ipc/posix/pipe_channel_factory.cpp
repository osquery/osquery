/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "pipe_channel_factory.h"

#include <unistd.h>

#include <array>
#include <stdexcept>
#include <string>

namespace osquery {

PipeChannelTicket::PipeChannelTicket(std::array<int, 2> read_pipe_fds,
                                     std::array<int, 2> write_pipe_fds)
    : read_pipe_fds_(read_pipe_fds), write_pipe_fds_(write_pipe_fds) {}

PipeChannelTicket PipeChannelFactory::createChannelTicket() {
  PipeChannelTicket ticket;
  auto result = pipe(ticket.read_pipe_fds_.data());

  if (result == -1) {
    throw std::runtime_error(
        "Failed to create parent_write_child_read_pipe, error: " +
        std::to_string(errno));
  }

  result = pipe(ticket.write_pipe_fds_.data());

  if (result == -1) {
    throw std::runtime_error(
        "Failed to create parent_read_child_write_pipe, error: " +
        std::to_string(errno));
  }

  return ticket;
}

PipeChannel& PipeChannelFactory::createChildChannel(
    const std::string& table_name, PipeChannelTicket channel_ticket) {
  return createChannel(table_name,
                       channel_ticket.getAndUseWriteFd(0),
                       channel_ticket.getAndUseReadFd(1));
}

PipeChannel& PipeChannelFactory::createParentChannel(
    const std::string& table_name,
    PipeChannelTicket channel_ticket,
    pid_t child_pid) {
  return createChannel(table_name,
                       channel_ticket.getAndUseReadFd(0),
                       channel_ticket.getAndUseWriteFd(1),
                       child_pid);
}

std::string PipeChannelFactory::getTableNameFromPid(pid_t pid) {
  for (const auto& pair : table_to_channel) {
    if (pair.second->getRemotePid() == pid) {
      return pair.second->table_name_;
    }
  }

  return "Not Connected";
}

std::unique_ptr<PipeChannel> PipeChannelFactory::createChannelImpl(
    const std::string& table_name,
    int read_pipe_fd,
    int write_pipe_fd,
    pid_t child_pid) {
  return std::make_unique<PipeChannel>(
      table_name, read_pipe_fd, write_pipe_fd, child_pid);
}

} // namespace osquery
