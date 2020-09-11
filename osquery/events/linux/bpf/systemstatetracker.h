/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/events/linux/bpf/isystemstatetracker.h>
#include <osquery/events/linux/bpf/utils.h>

#include <functional>
#include <memory>
#include <unordered_map>

#include <unistd.h>

namespace osquery {
class SystemStateTracker final : public ISystemStateTracker {
 public:
  using ProcessContextFactory = std::function<bool(ProcessContext&, pid_t)>;

  static Ref create();
  virtual ~SystemStateTracker() override;

  virtual bool createProcess(
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      pid_t child_process_id) override;

  virtual bool executeBinary(
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int dirfd,
      int flags,
      const std::string& binary_path,
      const tob::ebpfpub::IFunctionTracer::Event::Field::Argv& argv) override;

  virtual bool setWorkingDirectory(pid_t process_id, int dirfd) override;

  virtual bool setWorkingDirectory(pid_t process_id,
                                   const std::string& path) override;

  virtual bool openFile(pid_t process_id,
                        int dirfd,
                        int newfd,
                        const std::string& path,
                        int flags) override;

  virtual bool duplicateHandle(pid_t process_id,
                               int oldfd,
                               int newfd,
                               bool close_on_exec) override;

  virtual bool closeHandle(pid_t process_id, int fd) override;

  virtual EventList eventList() override;

 private:
  SystemStateTracker(ProcessContextFactory process_context_factory);

 public:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  struct Context final {
    ProcessContextMap process_map;
    EventList event_list;
  };

  static ProcessContext& getProcessContext(
      Context& context,
      ProcessContextFactory process_context_factory,
      pid_t process_id);

  static bool createProcess(
      Context& context,
      ProcessContextFactory process_context_factory,
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      pid_t child_process_id);

  static bool executeBinary(
      Context& context,
      ProcessContextFactory process_context_factory,
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int dirfd,
      int flags,
      const std::string& binary_path,
      const tob::ebpfpub::IFunctionTracer::Event::Field::Argv& argv);

  static bool setWorkingDirectory(Context& context,
                                  ProcessContextFactory process_context_factory,
                                  pid_t process_id,
                                  int dirfd);

  static bool setWorkingDirectory(Context& context,
                                  ProcessContextFactory process_context_factory,
                                  pid_t process_id,
                                  const std::string& path);

  static bool openFile(Context& context,
                       ProcessContextFactory process_context_factory,
                       pid_t process_id,
                       int dirfd,
                       int newfd,
                       const std::string& path,
                       int flags);

  static bool duplicateHandle(Context& context,
                              pid_t process_id,
                              int oldfd,
                              int newfd,
                              bool close_on_exec);

  static bool closeHandle(Context& context,
                          ProcessContextFactory process_context_factory,
                          pid_t process_id,
                          int fd);
};
} // namespace osquery
