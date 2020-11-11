/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include <osquery/events/linux/bpf/ifilesystem.h>

namespace osquery {

/// A structure collecting process data
struct ProcessContext final {
  /// An object describing a file descriptor
  struct FileDescriptor final {
    /// Path data for files
    struct FileData final {
      /// File or directory path
      std::string path;
    };

    /// Network information for sockets
    struct SocketData final {
      /// Domain type, as passed to socket()
      std::optional<int> opt_domain;

      /// Socket type, as passed to socket()
      std::optional<int> opt_type;

      /// Protocol type, as passed to socket()
      std::optional<int> opt_protocol;

      /// Local address, as passed to bind()
      std::optional<std::string> opt_local_address;

      /// Local port, as passed to bind()
      std::optional<std::uint16_t> opt_local_port;

      /// Remote address, as passed to connect() or received from accept()
      std::optional<std::string> opt_remote_address;

      /// Remote port, as passed to connect() or received from accept()
      std::optional<std::uint16_t> opt_remote_port;
    };

    /// File descriptor data
    std::variant<std::monostate, FileData, SocketData> data;

    /// If set to true, this file descriptor will be lost on execve
    bool close_on_exec{false};
  };

  using FileDescriptorMap = std::unordered_map<int, FileDescriptor>;

  /// Parent process id
  pid_t parent_process_id{};

  /// Current binary path
  std::string binary_path;

  /// Program argument list
  std::vector<std::string> argv;

  /// Current working directory
  std::string cwd;

  /// File descriptor map, automatically inherited when forking
  FileDescriptorMap fd_map;
};

using ProcessContextMap = std::unordered_map<pid_t, ProcessContext>;

/// \brief Factory class used to capture process information
/// This class is used to create ProcessContext objects based on
/// running processes using procfs.
///
/// Then BPF is used, osquery will take a full system snapshot which
/// is then kept up to date using the incoming events. In case one
/// of the processes is not found, the captureSingleProcess method
/// is used to add missing processes on the fly
class IProcessContextFactory {
 public:
  using Ref = std::unique_ptr<IProcessContextFactory>;
  static Status create(Ref& obj);

  /// Creates a context for the given process through procfs
  virtual bool captureSingleProcess(ProcessContext& process_context,
                                    pid_t process_id) const = 0;

  /// Creates a system snapshot, using captureSingleProcess on all processes
  virtual bool captureAllProcesses(ProcessContextMap& process_map) const = 0;

  IProcessContextFactory() = default;
  virtual ~IProcessContextFactory() = default;

  IProcessContextFactory(const IProcessContextFactory&) = delete;
  IProcessContextFactory& operator=(const IProcessContextFactory&) = delete;
};

} // namespace osquery
