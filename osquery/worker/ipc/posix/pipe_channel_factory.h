/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include "osquery/worker/ipc/table_channel_base.h"

#include "osquery/worker/ipc/posix/pipe_channel.h"
#include "osquery/worker/ipc/table_channel_factory_base.h"

namespace osquery {

class PipeChannelFactory;
template <>
struct GetChannelType<PipeChannelFactory> {
  using Channel = PipeChannel;
};

class PipeChannelTicket {
 public:
  ~PipeChannelTicket() {
    if (read_pipe_fds_[0] >= 0) {
      close(read_pipe_fds_[0]);
    }

    if (read_pipe_fds_[1] >= 0) {
      close(read_pipe_fds_[1]);
    }

    if (write_pipe_fds_[0] >= 0) {
      close(write_pipe_fds_[0]);
    }

    if (write_pipe_fds_[1] >= 0) {
      close(write_pipe_fds_[1]);
    }
  }

  int getAndUseReadFd(int index) {
    if (used_) {
      return -1;
    }

    return std::exchange(read_pipe_fds_[index], -1);
  }

  int getAndUseWriteFd(int index) {
    if (used_) {
      return -1;
    }

    return std::exchange(write_pipe_fds_[index], -1);
  }

  PipeChannelTicket(const PipeChannelTicket&) = delete;
  PipeChannelTicket& operator=(const PipeChannelTicket&) = delete;

  PipeChannelTicket(PipeChannelTicket&& other)
      : read_pipe_fds_(std::move(other.read_pipe_fds_)),
        write_pipe_fds_(std::move(other.write_pipe_fds_)),
        used_(other.used_) {
    if (used_) {
      throw std::logic_error("Constructed a used PipeChannelTicket");
    }

    other.invalidate();
  }

  PipeChannelTicket& operator=(PipeChannelTicket&& other) {
    if (other.used_) {
      throw std::logic_error(
          "Cannot move construct with a used PipeChannelTicket");
    }

    used_ = other.used_;
    read_pipe_fds_ = std::move(other.read_pipe_fds_);
    write_pipe_fds_ = std::move(other.write_pipe_fds_);
    other.invalidate();
    return *this;
  }

 private:
  PipeChannelTicket() = default;
  PipeChannelTicket(std::array<int, 2> read_pipe_fds_,
                    std::array<int, 2> write_pipe_fds_);

  void invalidate() {
    used_ = true;
    read_pipe_fds_.fill(-1);
    write_pipe_fds_.fill(-1);
  }

  std::array<int, 2> read_pipe_fds_{-1, -1};
  std::array<int, 2> write_pipe_fds_{-1, -1};

  bool used_{false};

  friend PipeChannelFactory;
};

class PipeChannelFactory : public TableChannelFactoryBase<PipeChannelFactory> {
 public:
  PipeChannelTicket createChannelTicket();
  PipeChannel& createChildChannel(const std::string& table_name,
                                  PipeChannelTicket channel_ticket);
  PipeChannel& createParentChannel(const std::string& table_name,
                                   PipeChannelTicket channel_ticket,
                                   pid_t child_pid);

  std::string getTableNameFromPid(pid_t pid);

 private:
  std::unique_ptr<PipeChannel> createChannelImpl(const std::string& table_name,
                                                 int read_pipe_fd,
                                                 int write_pipe_fd,
                                                 pid_t child_pid = 0);
  friend TableChannelFactoryBase<PipeChannelFactory>;
};
} // namespace osquery
