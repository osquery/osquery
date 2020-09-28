/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <ebpfpub/ifunctiontracer.h>
#include <ebpfpub/iperfeventreader.h>

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace osquery {
class ISystemStateTracker {
 public:
  using Ref = std::unique_ptr<ISystemStateTracker>;

  struct Event final {
    using BPFHeader = tob::ebpfpub::IFunctionTracer::Event::Header;

    enum class Type { Fork, Exec, Connect, Bind, Listen, Accept };

    struct ExecData final {
      std::vector<std::string> argv;
    };

    struct SocketData final {
      int domain{-1};
      int type{-1};
      int protocol{-1};

      int fd{-1};

      std::string local_address;
      std::uint16_t local_port{};

      std::string remote_address;
      std::uint16_t remote_port{};
    };

    using Data = std::variant<std::monostate, ExecData, SocketData>;

    Type type;

    pid_t parent_process_id{-1};
    std::string binary_path;
    std::string cwd;

    BPFHeader bpf_header;
    Data data;
  };

  using EventList = std::vector<Event>;

  ISystemStateTracker() = default;
  virtual ~ISystemStateTracker() = default;

  ISystemStateTracker(const ISystemStateTracker&) = delete;
  ISystemStateTracker& operator=(const ISystemStateTracker&) = delete;

  virtual bool createProcess(
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      pid_t child_process_id) = 0;

  virtual bool executeBinary(
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int dirfd,
      int flags,
      const std::string& binary_path,
      const tob::ebpfpub::IFunctionTracer::Event::Field::Argv& argv) = 0;

  virtual bool setWorkingDirectory(pid_t process_id, int dirfd) = 0;

  virtual bool setWorkingDirectory(pid_t process_id,
                                   const std::string& path) = 0;

  virtual bool openFile(pid_t process_id,
                        int dirfd,
                        int newfd,
                        const std::string& path,
                        int flags) = 0;

  virtual bool duplicateHandle(pid_t process_id,
                               int oldfd,
                               int newfd,
                               bool close_on_exec) = 0;

  virtual bool closeHandle(pid_t process_id, int fd) = 0;

  virtual bool createSocket(
      pid_t process_id, int domain, int type, int protocol, int fd) = 0;

  virtual bool bind(
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int fd,
      const std::vector<std::uint8_t>& sockaddr) = 0;

  virtual bool connect(
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int fd,
      const std::vector<std::uint8_t>& sockaddr) = 0;

  virtual EventList eventList() = 0;
};
} // namespace osquery
