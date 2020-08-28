/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "linux_table_ipc.h"

namespace osquery {
Status LinuxTableIPC::sendJSONString(const std::string& json_string) {
  if (active_channel_ == nullptr) {
    return Status::failure("No active channel to write to");
  }

  return active_channel_->sendStringMessage(json_string);
}

Status LinuxTableIPC::recvJSONString(std::string& json_string) {
  if (active_channel_ == nullptr) {
    return Status::failure("No active channel to read from");
  }

  return active_channel_->recvStringMessage(json_string);
}

Status LinuxTableIPC::processLogMessage(const JSON& json_message) {
  std::string message;
  int priority;
  int log_type_int;

  auto status = TableIPCJSONConverter::JSONToLogMessage(
      json_message, priority, log_type_int, message);

  if (!status.ok())
    return status;

  if (log_type_int != static_cast<int>(GLOGLogType::LOG) &&
      log_type_int != static_cast<int>(GLOGLogType::VLOG)) {
    return Status::failure("Received unknown log message type " +
                           std::to_string(log_type_int));
  }

  GLOGLogType log_type = static_cast<GLOGLogType>(log_type_int);

  return message_handler_->handleLog(log_type, priority, message);
}

Status LinuxTableIPC::processJobMessage(const JSON& json_message) {
  QueryContext context;

  auto status = deserializeQueryContextJSON(json_message, context);
  if (!status.ok()) {
    const std::string error_message =
        "Failed to deserialize the query context: " + status.getMessage();
    return Status::failure(error_message);
  }

  return message_handler_->handleJob(context);
}

Status LinuxTableIPC::processQueryDataMessage(const JSON& json_message,
                                              QueryData& query_results) {
  auto status =
      TableIPCJSONConverter::JSONToQueryData(json_message, query_results);

  if (!status.ok()) {
    return status;
  }

  return Status::success();
}

bool LinuxTableIPC::setActiveChannelIfOpen(const std::string table_name) {
  auto* channel = factory_->getTableChannel(table_name);

  if (!channel) {
    return false;
  }

  active_channel_ = channel;
  return true;
}

void LinuxTableIPC::connectToChild(const std::string table_name,
                                   PipeChannelTicket channel_ticket,
                                   pid_t child_pid) {
  active_channel_ = &factory_->createParentChannel(
      table_name, std::move(channel_ticket), child_pid);
}

void LinuxTableIPC::connectToParent(const std::string table_name,
                                    PipeChannelTicket channel_ticket) {
  active_channel_ =
      &factory_->createChildChannel(table_name, std::move(channel_ticket));
}

void LinuxTableIPC::closeActiveChannel() {
  if (active_channel_ == nullptr) {
    return;
  }

  factory_->dropTableChannel(active_channel_->table_name_);

  active_channel_ = nullptr;
}

std::string LinuxTableIPC::getTableNameFromPid(pid_t pid) {
  return factory_->getTableNameFromPid(pid);
}

} // namespace osquery
