/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/events/linux/bpf/iprocesscontextfactory.h>
#include <osquery/events/linux/bpf/isystemstatetracker.h>

#include <functional>
#include <memory>
#include <unordered_map>

#include <unistd.h>

namespace osquery {

class SystemStateTracker final : public ISystemStateTracker {
 public:
  static Ref create();
  static Ref create(IProcessContextFactory::Ref process_context_factory);

  virtual ~SystemStateTracker() override;

  virtual Status restart() override;

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

  virtual bool createSocket(
      pid_t process_id, int domain, int type, int protocol, int fd) override;

  virtual bool bind(
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int fd,
      const std::vector<std::uint8_t>& sockaddr) override;

  virtual bool listen(
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int fd) override;

  virtual bool connect(
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int fd,
      const std::vector<std::uint8_t>& sockaddr) override;

  virtual bool accept(
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int fd,
      const std::vector<std::uint8_t>& sockaddr,
      int newfd,
      int flags) override;

  virtual void nameToHandleAt(int dfd,
                              const std::string& name,
                              int handle_type,
                              const std::vector<std::uint8_t>& handle,
                              int mnt_id,
                              int flag) override;

  virtual bool openByHandleAt(pid_t process_id,
                              int mountdirfd,
                              int handle_type,
                              const std::vector<std::uint8_t>& handle,
                              int newfd) override;

  virtual EventList eventList() override;

  struct Context;
  Context getContextCopy() const;

 private:
  SystemStateTracker(IProcessContextFactory::Ref process_context_factory);

 public:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  struct FileHandleStruct final {
    int dfd{};
    std::string name;
    int flags{};
  };

  using FileHandleStructMap = std::unordered_map<std::string, FileHandleStruct>;

  struct Context final {
    ProcessContextMap process_map;
    EventList event_list;

    std::vector<std::string> file_handle_struct_index;
    FileHandleStructMap file_handle_struct_map;
  };

  static ProcessContext& getProcessContext(
      Context& context,
      IProcessContextFactory& process_context_factory,
      pid_t process_id);

  static Status expireProcessContexts(Context& context, IFilesystem& fs);

  static bool createProcess(
      Context& context,
      IProcessContextFactory& process_context_factory,
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      pid_t child_process_id);

  static bool executeBinary(
      Context& context,
      IProcessContextFactory& process_context_factory,
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int dirfd,
      int flags,
      const std::string& binary_path,
      const tob::ebpfpub::IFunctionTracer::Event::Field::Argv& argv);

  static bool setWorkingDirectory(
      Context& context,
      IProcessContextFactory& process_context_factory,
      pid_t process_id,
      int dirfd);

  static bool setWorkingDirectory(
      Context& context,
      IProcessContextFactory& process_context_factory,
      pid_t process_id,
      const std::string& path);

  static bool openFile(Context& context,
                       IProcessContextFactory& process_context_factory,
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
                          IProcessContextFactory& process_context_factory,
                          pid_t process_id,
                          int fd);

  static bool createSocket(Context& context,
                           IProcessContextFactory& process_context_factory,
                           pid_t process_id,
                           int domain,
                           int type,
                           int protocol,
                           int fd);

  static bool bind(
      Context& context,
      IProcessContextFactory& process_context_factory,
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int fd,
      const std::vector<std::uint8_t>& sockaddr);

  static bool listen(
      Context& context,
      IProcessContextFactory& process_context_factory,
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int fd);

  static bool connect(
      Context& context,
      IProcessContextFactory& process_context_factory,
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int fd,
      const std::vector<std::uint8_t>& sockaddr);

  static bool accept(
      Context& context,
      IProcessContextFactory& process_context_factory,
      const tob::ebpfpub::IFunctionTracer::Event::Header& event_header,
      pid_t process_id,
      int fd,
      const std::vector<std::uint8_t>& sockaddr,
      int newfd,
      int flags);

  static bool openByHandleAt(Context& context,
                             IProcessContextFactory& process_context_factory,
                             pid_t process_id,
                             int mountdirfd,
                             int handle_type,
                             const std::vector<std::uint8_t>& handle,
                             int newfd);

  static bool parseUnixSockaddr(std::string& path,
                                const std::vector<std::uint8_t>& sockaddr);

  static bool parseInetSockaddr(std::string& address,
                                std::uint16_t& port,
                                const std::vector<std::uint8_t>& sockaddr);

  static bool parseNetlinkSockaddr(std::string& address,
                                   std::uint16_t& port,
                                   const std::vector<std::uint8_t>& sockaddr);

  static bool parseInet6Sockaddr(std::string& address,
                                 std::uint16_t& port,
                                 const std::vector<std::uint8_t>& sockaddr);

  static bool parseSocketAddress(
      ProcessContext::FileDescriptor::SocketData& socket_data,
      const std::vector<std::uint8_t>& sockaddr,
      bool local);

  static std::string createFileHandleIndex(
      int handle_type, const std::vector<std::uint8_t>& handle);

  static void saveFileHandle(Context& context,
                             int dfd,
                             const std::string& name,
                             int handle_type,
                             const std::vector<std::uint8_t>& handle,
                             int mnt_id,
                             int flag);

  static void expireFileHandleEntries(Context& context, std::size_t max_size);
};

} // namespace osquery
