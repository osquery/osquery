/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "pipe_channel.h"

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <limits>

namespace osquery {
PipeChannel::PipeChannel(const std::string& table_name,
                         int read_pipe_fd,
                         int write_pipe_fd,
                         pid_t remote_pid)
    : TableChannelBase<PipeChannel>(table_name),
      read_pipe_fd(read_pipe_fd),
      write_pipe_fd(write_pipe_fd),
      remote_pid(remote_pid) {}

Status PipeChannel::sendStringMessageImpl(const std::string& message) {
  if (message.size() == 0) {
    return Status::failure("Cannot send a zero length message");
  }

  if (message.size() > std::numeric_limits<ssize_t>::max()) {
    return Status::failure("Cannot send, message too big, " +
                           std::to_string(message.size()) + " bytes");
  }

  const ssize_t message_size = static_cast<ssize_t>(message.size());

  auto old_mask = blockSIGPIPE();

  ssize_t result = write(write_pipe_fd,
                         reinterpret_cast<const char*>(&message_size),
                         sizeof(message_size));

  if (result < 0) {
    restoreSIGPIPE(old_mask);
    return Status::failure(
        errno,
        "Failed to write the size of the message through the pipe of table " +
            table_name_ + ", errno " + std::to_string(errno));
  }

  if (result != sizeof(message_size)) {
    restoreSIGPIPE(old_mask);
    return Status::failure(
        "Failed to write the entire size of the message through the pipe of "
        "table " +
        table_name_ + ", sent only " + std::to_string(result) + "/" +
        std::to_string(message_size) + " bytes");
  }

  result = write(write_pipe_fd, &message[0], static_cast<size_t>(message_size));

  restoreSIGPIPE(old_mask);

  if (result < 0) {
    return Status::failure(
        errno,
        "Failed to write the message through the pipe of table " + table_name_ +
            ", errno " + std::to_string(errno));
  }

  if (result != message_size) {
    return Status::failure("Failed to send the entire message of table " +
                           table_name_ + ", sent only " +
                           std::to_string(result) + "/" +
                           std::to_string(message_size));
  }

  return Status::success();
}

Status PipeChannel::recvStringMessageImpl(std::string& message) {
  ssize_t message_size;
  ssize_t result = read(read_pipe_fd,
                        reinterpret_cast<char*>(&message_size),
                        sizeof(message_size));

  if (result < 0) {
    return Status::failure(
        errno,
        "Failed to read the size of the message from the pipe of table " +
            table_name_ + ", errno " + std::to_string(errno));
  }

  if (result == 0) {
    return Status::failure(
        2, "Pipe to the table " + table_name_ + " closed while reading");
  }

  if (result != sizeof(message_size)) {
    return Status::failure(
        "Failed to read the entire size of the message from the pipe of "
        "table " +
        table_name_ + ", read only " + std::to_string(result) + "/" +
        std::to_string(sizeof(message_size)) + " bytes");
  }

  if (message_size <= 0) {
    return Status::failure("Message size too small, it's " +
                           std::to_string(message_size) + " bytes");
  }

  message.resize(static_cast<size_t>(message_size));
  ssize_t pos = 0;
  while (pos < message_size) {
    result = read(read_pipe_fd,
                  reinterpret_cast<char*>(&message[pos]),
                  static_cast<size_t>(message_size - pos));

    if (result == 0) {
      return Status::failure(
          2, "Pipe to the table " + table_name_ + " closed while reading");
    }

    if (result < 0) {
      return Status::failure(
          errno,
          "Failed to read the message from the pipe of table " + table_name_ +
              ", errno " + std::to_string(errno));
    }
    pos += result;
  }

  return Status::success();
}

sigset_t PipeChannel::blockSIGPIPE() {
  sigset_t new_mask;
  sigset_t old_mask;

  sigemptyset(&new_mask);
  sigaddset(&new_mask, SIGPIPE);

  pthread_sigmask(SIG_BLOCK, &new_mask, &old_mask);

  return old_mask;
}

void PipeChannel::restoreSIGPIPE(const sigset_t& old_mask) {
  pthread_sigmask(SIG_UNBLOCK, &old_mask, nullptr);
}
} // namespace osquery
