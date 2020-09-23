/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include <osquery/events/linux/bpf/ifilesystem.h>

namespace osquery {
struct ProcessContext final {
  struct FileDescriptor final {
    std::string path;
    bool close_on_exec{false};
  };

  using FileDescriptorMap = std::unordered_map<int, FileDescriptor>;

  pid_t parent_process_id{};

  std::string binary_path;
  std::vector<std::string> argv;

  std::string cwd;
  FileDescriptorMap fd_map;
};

using ProcessContextMap = std::unordered_map<pid_t, ProcessContext>;

class IProcessContextFactory {
 public:
  using Ref = std::unique_ptr<IProcessContextFactory>;
  static Status create(Ref& obj);

  virtual bool captureSingleProcess(ProcessContext& process_context,
                                    pid_t process_id) const = 0;

  virtual bool captureAllProcesses(ProcessContextMap& process_map) const = 0;

  IProcessContextFactory() = default;
  virtual ~IProcessContextFactory() = default;

  IProcessContextFactory(const IProcessContextFactory&) = delete;
  IProcessContextFactory& operator=(const IProcessContextFactory&) = delete;
};
} // namespace osquery
