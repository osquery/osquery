/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "linux_table_container_ipc.h"

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syscall.h>
#include <syslog.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <iostream>

#include <osquery/core/flags.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/worker/ipc/posix/pipe_channel_factory.h>
#include <osquery/worker/ipc/table_ipc_json_converter.h>

#include "osquery/worker/logging/glog/glog_logger.h"

namespace osquery {

DECLARE_bool(verbose);

CLI_FLAG(bool,
         keep_container_worker_open,
         false,
         "Keep the container worker running to be reused instead of closing it "
         "after each query");

namespace {

const std::string kProc = "/proc";
const std::string kMountNamespace = "/ns/mnt";

/*
 * A namespace id as read from the pseudo link /proc/<pid>/ns/mnt
 * has the format mnt:[<id>] where <id> is an unsigned int representing
 * the namespace id; the max value of an unsigned int has 10 digits
 * and the rest of the string are 6 characters, so the content
 * of the link is max 16 characters.
 */
const int kMaxNamespaceIdLinkChars = 16;

PlatformProcess current_running_process;

Status extractMountNamespaceId(const std::string& mount_namespace_path,
                               std::string& mount_namespace_id) {
  std::string mnt_namespace_id_source(kMaxNamespaceIdLinkChars, 0);
  auto chars_read = readlink(mount_namespace_path.data(),
                             &mnt_namespace_id_source[0],
                             mnt_namespace_id_source.size());

  if (chars_read < 0) {
    return Status::failure("Could not read the mount namespace id from " +
                           mount_namespace_path +
                           ", error: " + std::to_string(errno));
  }

  mnt_namespace_id_source.resize(static_cast<size_t>(chars_read));

  if (mnt_namespace_id_source.empty()) {
    return Status::failure(
        "Failed to parse the mount namespace id, string is empty");
  }

  auto start = mnt_namespace_id_source.find('[');

  if (start == std::string::npos) {
    return Status::failure(
        "Failed to find the start of the mount namespace id in \"" +
        mnt_namespace_id_source + "\"");
  }

  auto end = mnt_namespace_id_source.find(']', start);

  if (end == std::string::npos) {
    return Status::failure(
        "Failed to find the end of the mount namespace id in \"" +
        mnt_namespace_id_source + "\"");
  }

  size_t namespace_id_size = end - start - 1;

  if (namespace_id_size == 0) {
    return Status::failure(
        "Failed to parse the mount namespace id, no id found");
  }

  mount_namespace_id =
      mnt_namespace_id_source.substr(start + 1, namespace_id_size);

  return Status::success();
}

ProcessState checkProcessStateAndLog(const PlatformProcess& process,
                                     const std::string& table_name) {
  int child_exit_status = 0;

  ProcessState process_state = process.checkStatus(child_exit_status);

  if (process_state == ProcessState::PROCESS_ERROR) {
    LOG(ERROR)
        << "Failed to get the process state of container worker of table "
        << table_name << " with pid " << process.pid();
  } else if (process_state == ProcessState::PROCESS_EXITED &&
             child_exit_status != 0) {
    std::string message =
        "Container worker of table " + table_name +
        " exited with exit status: " + std::to_string(child_exit_status);
    if (child_exit_status == 2 && FLAGS_verbose) {
      syslog(LOG_NOTICE, "%s", message.c_str());
    } else {
      LOG(ERROR) << message;
    }
  }

  return process_state;
}
} // namespace

extern template std::set<int> ConstraintList::getAll<int>(
    ConstraintOperator) const;

LinuxTableContainerIPC::LinuxTableContainerIPC(PipeChannelFactory& factory)
    : ipc_(factory, *this) {}

LinuxTableContainerIPC::~LinuxTableContainerIPC() {
  close(original_mnt_fd_);
}

Status LinuxTableContainerIPC::connectToContainer(
    const std::string& table_name,
    bool keep_process_open,
    TableGeneratePtr function_ptr) {
  keep_process_open_ = keep_process_open;

  auto current_pid = getpid();
  std::string original_mnt_path =
      kProc + "/" + std::to_string(current_pid) + kMountNamespace;

  if (original_mnt_fd_ > 0) {
    close(original_mnt_fd_);
  }

  original_mnt_fd_ = open(original_mnt_path.c_str(), O_RDONLY);

  if (original_mnt_fd_ < 0) {
    return Status::failure(
        "Failed to open the original mount namespace of the worker");
  }

  bool is_open = ipc_.setActiveChannelIfOpen(table_name);

  if (!is_open) {
    // This will stop any worker connected to another table,
    // so that we only have one open each time
    if (keep_process_open_) {
      stopContainerWorker();
    }

    PipeChannelTicket channel_ticket = ipc_.createChannelTicket();

    auto process_group = getpgrp();
    table_generate_ptr_ = function_ptr;

    pid_t pid = fork();

    if (pid == 0) {
      auto result = setpgid(0, process_group);

      if (result < 0) {
        std::_Exit(1);
      }

      try {
        ipc_.connectToParent(table_name, std::move(channel_ticket));
      } catch (const std::exception& e) {
        syslog(LOG_NOTICE, "Failed to connect to parent: %s", e.what());
        std::_Exit(1);
      }

      executeQueryJobs();
    } else if (pid == -1) {
      return Status::failure("Failed to start container worker to table " +
                             table_name);
    } else {
      current_running_process = PlatformProcess(pid);
      ipc_.connectToChild(table_name, std::move(channel_ticket), pid);
    }
  }

  return Status::success();
}
void LinuxTableContainerIPC::stopContainerWorker() {
  PlatformProcess child_process(std::move(current_running_process));

  if (child_process.pid() == kInvalidPid) {
    return;
  }

  std::string table_name = ipc_.isChannelOpen()
                               ? ipc_.getTableName()
                               : ipc_.getTableNameFromPid(child_process.pid());

  ipc_.setActiveChannelIfOpen(table_name);
  ipc_.closeActiveChannel();

  ProcessState process_state =
      checkProcessStateAndLog(child_process, table_name);

  if (process_state == ProcessState::PROCESS_STILL_ALIVE) {
    // Wait for the process to close on a separate thread.
    // If it doesn't close in a timely fashion it will be forcefully terminated.
    auto wait_and_kill = [](PlatformProcess process, std::string table_name) {
      auto time_passed = std::chrono::milliseconds(0);
      auto interval = std::chrono::milliseconds(500);
      auto max_delay = std::chrono::milliseconds(2000);

      ProcessState process_state = ProcessState::PROCESS_STILL_ALIVE;
      while (time_passed < max_delay) {
        sleepFor(static_cast<size_t>(interval.count()));
        time_passed += interval;

        process_state = checkProcessStateAndLog(process, table_name);

        if (process_state == ProcessState::PROCESS_ERROR ||
            process_state == ProcessState::PROCESS_EXITED) {
          break;
        }
      }

      if (process_state == ProcessState::PROCESS_STILL_ALIVE) {
        LOG(ERROR) << "Container worker to table " << table_name << " and pid "
                   << process.pid()
                   << " did not stop in a timely fashion, so it will be "
                      "forcefully terminated";
        process.kill();
        process.cleanup(max_delay);
      }
    };

    auto wait_and_kill_thread =
        std::thread(wait_and_kill, std::move(child_process), table_name);
    wait_and_kill_thread.detach();
  }
}

Status LinuxTableContainerIPC::handleLog(GLOGLogType log_type,
                                         int priority,
                                         const std::string& message) {
  auto logger = GLOGLogger::instance();
  switch (log_type) {
  case GLOGLogType::LOG: {
    logger.log(priority, message);
    break;
  }
  case GLOGLogType::VLOG: {
    logger.vlog(priority, message);
    break;
  }
  default: {
    return Status::failure("Unknown log message type " +
                           std::to_string(static_cast<int>(log_type)));
  }
  }

  return Status::success();
}

Status LinuxTableContainerIPC::handleJob(QueryContext& context) {
  QueryData query_data;
  auto pids_with_namespace =
      context.constraints.at("pid_with_namespace").getAll<int>(EQUALS);

  if (pids_with_namespace.empty()) {
    return Status::failure(
        "Column constraint pid_with_namespace has been passed but there's no "
        "value in it");
  }

  for (const auto pid : pids_with_namespace) {
    std::string path = kProc + "/" + std::to_string(pid) + kMountNamespace;
    auto fd = open(path.c_str(), O_RDONLY);

    if (fd < 0) {
      logger_.vlog(1,
                   "Could not open mount namespace of pid " +
                       std::to_string(pid) +
                       ", error: " + std::to_string(errno));
      continue;
    }

    std::string mount_namespace_id;
    auto status = extractMountNamespaceId(path, mount_namespace_id);

    if (!status.ok()) {
      logger_.vlog(1, status.getMessage());
      close(fd);
      continue;
    }

    // We call the syscall directly because setns() has been added as a function
    // from glibc 2.14 and on only.
    int result = static_cast<int>(syscall(SYS_setns, fd, 0));

    close(fd);

    if (result < 0) {
      logger_.vlog(1,
                   "Could not switch namespace of pid " + std::to_string(pid) +
                       ", error: " + std::to_string(errno));
      continue;
    }

    QueryData namespace_query_data = table_generate_ptr_(context, logger_);
    for (auto& row : namespace_query_data) {
      row["pid_with_namespace"] = INTEGER(pid);
      row["mount_namespace_id"] = mount_namespace_id;
    }

    query_data.insert(query_data.end(),
                      std::make_move_iterator(namespace_query_data.begin()),
                      std::make_move_iterator(namespace_query_data.end()));
  }

  /*
    While we still want to return results to the parent,
    but not being able to restore the original namespace means that
    if the child is kept around, it won't be able to be reused.
    So after delivering the results, we return with an error so
    that the process will be always closed.
  */
  auto write_status = ipc_.sendQueryData(query_data);

  if (keep_process_open_) {
    int result = static_cast<int>(syscall(SYS_setns, original_mnt_fd_, 0));

    if (result < 0) {
      auto status = Status::failure(
          "Failed to restore the original mount namespace, due to error: " +
          std::to_string(errno));
      logger_.vlog(1, status.getMessage());
      return status;
    }
  }

  return write_status;
}

void LinuxTableContainerIPC::executeQueryJobs() {
  int exit_status_code = 0;
  if (keep_process_open_) {
    while (true) {
      JSONMessageType message_type;
      auto status = ipc_.processOneMessage(nullptr, message_type);

      if (!status.ok()) {
        exit_status_code = status.getCode();

        if (exit_status_code != 2 || FLAGS_verbose) {
          syslog(LOG_NOTICE, "%s", status.getMessage().c_str());
        }
        break;
      }
    }
  } else {
    JSONMessageType message_type;
    auto status = ipc_.processOneMessage(nullptr, message_type);

    if (!status.ok()) {
      exit_status_code = status.getCode();

      if (exit_status_code != 2 || FLAGS_verbose) {
        syslog(LOG_NOTICE, "%s", status.getMessage().c_str());
      }
    }
  }

  std::_Exit(exit_status_code);
}

Status LinuxTableContainerIPC::retrieveQueryDataFromContainer(
    const QueryContext& context, QueryData& result) {
  CleanupWorkerOnError cleanupOnError(*this);
  auto status = ipc_.sendJob(context);

  if (!status.ok()) {
    return status;
  }

  bool child_has_result = false;
  while (!child_has_result) {
    JSONMessageType message_type;
    auto status = ipc_.processOneMessage(&result, message_type);

    if (!status.ok())
      return status;

    if (message_type == JSONMessageType::QueryData) {
      child_has_result = true;
    }
  }

  cleanupOnError.dismiss();
  return status;
}

QueryData generateInNamespace(const QueryContext& context,
                              const std::string& table_name,
                              TableGeneratePtr generate_ptr) {
  bool keep_container_worker_open = FLAGS_keep_container_worker_open;
  QueryData results;

  static PipeChannelFactory factory;

  try {
    LinuxTableContainerIPC ipc(factory);
    auto status = ipc.connectToContainer(
        table_name, keep_container_worker_open, generate_ptr);

    if (!status.ok()) {
      LOG(ERROR) << "Table " << table_name
                 << " failed to connect to the container: "
                 << status.getMessage();
      return results;
    }

    status = ipc.retrieveQueryDataFromContainer(context, results);

    if (!status.ok()) {
      LOG(ERROR) << "Table " << table_name
                 << " failed to retrieve QueryData from the container: "
                 << status.getMessage();
    }

    if (!keep_container_worker_open)
      ipc.stopContainerWorker();
  } catch (const std::exception& e) {
    LOG(ERROR) << "Table " << table_name
               << " failed to run query in the container: " << e.what();
  }

  return results;
}

}; // namespace osquery
