/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/process/process.h>
#include <osquery/utils/status/status.h>

#include "osquery/worker/ipc/table_channel_base.h"

namespace osquery {
class PipeChannelFactory;

class PipeChannel : public TableChannelBase<PipeChannel> {
 public:
  PipeChannel() = delete;
  PipeChannel(const std::string& table_name,
              int read_pipe_fd,
              int write_pipe_fd,
              pid_t remote_pid);
  ~PipeChannel() {
    close(read_pipe_fd);
    close(write_pipe_fd);
  }

  pid_t getRemotePid() {
    return remote_pid;
  }

 private:
  friend TableChannelBase<PipeChannel>;

  Status sendStringMessageImpl(const std::string& message);
  Status recvStringMessageImpl(std::string& message);

  sigset_t blockSIGPIPE();
  void restoreSIGPIPE(const sigset_t& old_mask);

  const int read_pipe_fd;
  const int write_pipe_fd;
  const pid_t remote_pid;
};
} // namespace osquery
