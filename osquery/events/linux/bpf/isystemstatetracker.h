/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <ebpfpub/ifunctiontracer.h>
#include <ebpfpub/iperfeventreader.h>

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace osquery {

/// \brief A state tracker that emits events based on the incoming events
/// The system state tracker starts from a full procfs-based system
/// snapshot, and uses the events it receives to keep it up to date
/// and emit events when certain actions happen (example: process creation)
class ISystemStateTracker {
 public:
  using Ref = std::unique_ptr<ISystemStateTracker>;

  /// A system call event
  struct Event final {
    using BPFHeader = tob::ebpfpub::IFunctionTracer::Event::Header;

    /// Event groups. Fork; fork/vfork/clone, Exec: execve/execveat
    enum class Type { Fork, Exec, Connect, Bind, Listen, Accept };

    /// Event data for execve and execveat events
    struct ExecData final {
      std::vector<std::string> argv;
    };

    /// Event data for connect/listen/bind/accept events
    struct SocketData final {
      /// Domain type, as specified to socket()
      int domain{-1};

      /// Socket type, as specified to socket()
      int type{-1};

      /// Protocol type, as specified to socket()
      int protocol{-1};

      /// File descriptor value
      int fd{-1};

      /// Local address, as specified to bind()
      std::string local_address;

      /// Local port, as specified to bind()
      std::uint16_t local_port{};

      /// Remote address, as specified to connect() or received by accept()
      std::string remote_address;

      /// Remote address, as specified to connect() or received by accept()
      std::uint16_t remote_port{};
    };

    using Data = std::variant<std::monostate, ExecData, SocketData>;

    /// Event type
    Type type;

    /// Parent process id
    pid_t parent_process_id{-1};

    /// Binary path
    std::string binary_path;

    /// Current working directory
    std::string cwd;

    /// The BPF event header, as received from ebpfpub
    BPFHeader bpf_header;

    /// Event data
    Data data;
  };

  using EventList = std::vector<Event>;

  ISystemStateTracker() = default;
  virtual ~ISystemStateTracker() = default;

  ISystemStateTracker(const ISystemStateTracker&) = delete;
  ISystemStateTracker& operator=(const ISystemStateTracker&) = delete;

  /// \brief Resets the internal state, taking a new /proc snapshot
  virtual Status restart() = 0;

  /// \brief Creates a new process, in response to an fork, vfork or clone
  /// syscall Once the method has updated the internal state, it will also emit
  /// a new event
  virtual bool createProcess(
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      pid_t child_process_id) = 0;

  /// \brief Executes a new binary, in response to execve/execveat
  /// This method updates a process context by emulating what happens when
  /// an exec is called. This means not only updating the binary path but
  /// also closing all the file descriptors that are not supposed to be
  /// inherited (close on exec)
  /// The parameters follow the execveat() documentation found in the man
  /// pages
  /// This method will generate a new event
  virtual bool executeBinary(
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int dirfd,
      int flags,
      const std::string& binary_path,
      const tob::ebpfpub::IFunctionTracer::Event::Field::Argv& argv) = 0;

  /// Sets the process working directory, in response to fchdir
  virtual bool setWorkingDirectory(pid_t process_id, int dirfd) = 0;

  /// Sets the process working directory, in response to chdir
  virtual bool setWorkingDirectory(pid_t process_id,
                                   const std::string& path) = 0;

  /// \brief Opens a new file or folder, based on the specified flags
  /// This method will either open a new file or a new folder if the
  /// O_DIRECTORY flag is specified. The parameters follow the openat
  /// documentation found in the man pages
  virtual bool openFile(pid_t process_id,
                        int dirfd,
                        int newfd,
                        const std::string& path,
                        int flags) = 0;

  /// \brief Duplicates the given handle
  /// This method is used to duplicate handles in response to the
  /// following syscalls: dup, dup2, dup3, fcntl + F_DUPFD/F_DUPFD_CLOEXEC
  virtual bool duplicateHandle(pid_t process_id,
                               int oldfd,
                               int newfd,
                               bool close_on_exec) = 0;

  /// Closes the given file handle
  virtual bool closeHandle(pid_t process_id, int fd) = 0;

  /// \brief Creates a new socket in response to socket()
  /// When handling sockaddr structures, we sometimes need the data passed
  /// to the socket() system call when the address family is set to
  /// AF_UNSPEC
  virtual bool createSocket(
      pid_t process_id, int domain, int type, int protocol, int fd) = 0;

  /// \brief Updates the socket data for the given fd in response to bind
  /// This method will update the process file descriptor and then emit
  /// a new event
  virtual bool bind(
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int fd,
      const std::vector<std::uint8_t>& sockaddr) = 0;

  /// \brief Updates the socket data for the given fd in response to listen
  /// This method will update the process file descriptor and then emit
  /// a new event
  virtual bool listen(
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int fd) = 0;

  /// \brief Updates the socket data for the given fd in response to connect
  /// This method will update the process file descriptor and then emit
  /// a new event
  virtual bool connect(
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int fd,
      const std::vector<std::uint8_t>& sockaddr) = 0;

  /// \brief Creates a new file descriptor in response to accept and accept4
  /// This method will create a new file descriptor and then emit an event
  virtual bool accept(
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int fd,
      const std::vector<std::uint8_t>& sockaddr,
      int newfd,
      int flags) = 0;

  /// \brief Tracks name_to_handle_at usage
  /// This method will track opaque FDs created with name_to_handle_at
  virtual void nameToHandleAt(int dfd,
                              const std::string& name,
                              int handle_type,
                              const std::vector<std::uint8_t>& handle,
                              int mnt_id,
                              int flag) = 0;

  /// \brief Opens a file through a file_handle structure
  /// This method will open a file using a previously tracked file_handle
  virtual bool openByHandleAt(pid_t process_id,
                              int mountdirfd,
                              int handle_type,
                              const std::vector<std::uint8_t>& handle,
                              int newfd) = 0;

  /// Returns the list of generated events
  virtual EventList eventList() = 0;
};

} // namespace osquery
