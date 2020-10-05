/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/worker/ipc/posix/pipe_channel.h>
#include <osquery/worker/ipc/posix/pipe_channel_factory.h>

#include "osquery/worker/ipc/table_ipc_base.h"
#include "osquery/worker/ipc/table_ipc_message_handler.h"
#include "osquery/worker/logging/glog_logger_types.h"
#include "osquery/worker/logging/logger.h"

namespace osquery {

/**
 * @brief The LinuxTableIPC class manages the communication and connection
 * between processes handling table logic, using JSON as message protocol and
 * blocking pipes as communication channel.
 *
 */
class LinuxTableIPC : public TableIPCBase<LinuxTableIPC> {
 public:
  LinuxTableIPC(PipeChannelFactory& factory,
                TableIPCMessageHandler& message_handler)
      : factory_(&factory), message_handler_(&message_handler) {}

  Status sendJSONString(const std::string& json_string);
  Status recvJSONString(std::string& json_string);

  Status processLogMessage(const JSON& json_message);
  Status processJobMessage(const JSON& json_message);
  Status processQueryDataMessage(const JSON& json_message,
                                 QueryData& query_results);

  PipeChannelTicket createChannelTicket() {
    return factory_->createChannelTicket();
  }
  bool setActiveChannelIfOpen(const std::string table_name);
  void connectToChild(const std::string table_name,
                      PipeChannelTicket channel_ticket,
                      pid_t child_pid);
  void connectToParent(const std::string table_name,
                       PipeChannelTicket channel_ticket);
  void closeActiveChannel();

  std::string getTableNameFromPid(pid_t pid);

  bool isChannelOpen() {
    return active_channel_ != nullptr;
  };

  pid_t getRemotePid() {
    return active_channel_ ? active_channel_->getRemotePid() : -1;
  }
  std::string getTableName() {
    return active_channel_ ? active_channel_->table_name_ : "Not Connected";
  }

 private:
  PipeChannel* active_channel_{nullptr};
  PipeChannelFactory* factory_;
  TableIPCMessageHandler* message_handler_;
};

class LinuxTableIPCLogger final : public Logger {
 public:
  LinuxTableIPCLogger() = delete;
  LinuxTableIPCLogger(LinuxTableIPC& ipc) : ipc(&ipc) {}

  void log(int severity, const std::string& message) override {
    ipc->sendLogMessage(severity, GLOGLogType::LOG, message);
  }

  void vlog(int priority, const std::string& message) override {
    ipc->sendLogMessage(priority, GLOGLogType::VLOG, message);
  }

  LinuxTableIPC* ipc;
};
} // namespace osquery
