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

#include <unistd.h>

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

bool readLinkAt(std::string& destination,
                int dirfd,
                const std::string& relative_path);

bool readFileAt(std::vector<char>& buffer,
                int dirfd,
                const std::string& relative_path);

bool queryProcessArgv(std::vector<std::string>& argv, int procs_fd);

bool queryProcessParentID(pid_t& parent_pid, int procs_fd);

bool queryProcessFileDescriptorMap(ProcessContext::FileDescriptorMap& fd_map,
                                   int procs_fd);

bool createProcessContext(ProcessContext& process_context, pid_t process_id);

bool createProcessContextMap(ProcessContextMap& process_map);
} // namespace osquery
