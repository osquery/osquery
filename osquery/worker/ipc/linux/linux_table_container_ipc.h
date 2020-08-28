/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include "osquery/worker/ipc/linux/linux_table_ipc.h"

#include <string>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/status/status.h>

#include "osquery/worker/ipc/posix/pipe_channel.h"
#include "osquery/worker/ipc/posix/pipe_channel_factory.h"
#include "osquery/worker/ipc/table_ipc_message_handler.h"
#include "osquery/worker/logging/glog_logger_types.h"
#include "osquery/worker/logging/logger.h"

namespace osquery {
using TableGeneratePtr = QueryData (*)(QueryContext& query_context,
                                       Logger& logger_);

/**
 * @brief The LinuxTableContainerIPC class drives the logic to connect to, query
 * and retrieve results from a container, together with managing the container
 * worker lifetime.
 */
class LinuxTableContainerIPC : TableIPCMessageHandler {
 public:
  LinuxTableContainerIPC() = delete;
  LinuxTableContainerIPC(PipeChannelFactory& factory);
  ~LinuxTableContainerIPC();

  Status connectToContainer(const std::string& table_name,
                            bool keep_process_open,
                            TableGeneratePtr table_generate_ptr_);
  Status retrieveQueryDataFromContainer(const QueryContext& context,
                                        QueryData& result);
  [[noreturn]] void executeQueryJobs();
  void stopContainerWorker();

  Status handleLog(GLOGLogType log_type,
                   int priority,
                   const std::string& message) override;
  Status handleJob(QueryContext& context) override;

 private:
  LinuxTableIPC ipc_;
  LinuxTableIPCLogger logger_{ipc_};
  TableGeneratePtr table_generate_ptr_;
  bool keep_process_open_{false};
  int original_mnt_fd_{-1};

  class CleanupWorkerOnError {
   public:
    CleanupWorkerOnError() = delete;
    CleanupWorkerOnError(LinuxTableContainerIPC& container_ipc)
        : container_ipc_(&container_ipc) {}
    ~CleanupWorkerOnError() {
      if (cleanup_)
        container_ipc_->stopContainerWorker();
    }

    void dismiss() {
      cleanup_ = false;
    }

   private:
    LinuxTableContainerIPC* container_ipc_;
    bool cleanup_{true};
  };

  FRIEND_TEST(WorkerTableContainerTests, test_ipc_container_connect);
};

inline bool hasNamespaceConstraint(const QueryContext& context) {
  return context.hasConstraint("pid_with_namespace");
}

QueryData generateInNamespace(const QueryContext& context,
                              const std::string& table_name,
                              TableGeneratePtr generate_ptr);
} // namespace osquery
