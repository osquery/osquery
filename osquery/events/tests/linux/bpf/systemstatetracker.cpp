/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "bpftestsmain.h"
#include "mockedfilesystem.h"
#include "mockedprocesscontextfactory.h"
#include "utils.h"

#include <osquery/events/linux/bpf/systemstatetracker.h>

#include <arpa/inet.h>
#include <linux/fcntl.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

namespace osquery {

namespace {

// clang-format off
const tob::ebpfpub::IFunctionTracer::Event::Header kBaseBPFEventHeader {
  // nsecs timestamp, starting from the system boot
  0U,

  // thread id
  1001,

  // process id
  1001,

  // user id
  1000,

  // group id
  1000,

  // cgroup id
  1000,

  // exit code
  0,

  // probe error
  false
};
// clang-format on

const std::vector<std::uint8_t> kTestUnixSocketAddress = {
    0x01, 0x00, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x2f, 0x70, 0x61, 0x74,
    0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

const std::vector<std::uint8_t> kTestIPv4Address = {0x02,
                                                    0x00,
                                                    0x00,
                                                    0x50,
                                                    0xc0,
                                                    0xa8,
                                                    0x01,
                                                    0x02,
                                                    0x00,
                                                    0x00,
                                                    0x00,
                                                    0x00,
                                                    0x00,
                                                    0x00,
                                                    0x00,
                                                    0x00};

const std::vector<std::uint8_t> kTestIPv6Address = {
    0x0a, 0x00, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x00, 0x00, 0x00};

const std::vector<std::uint8_t> kTestNetlinkSockaddr = {
    0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};

} // namespace

TEST_F(SystemStateTrackerTests, getProcessContext) {
  auto process_context_factory =
      std::make_unique<MockedProcessContextFactory>();

  SystemStateTracker::Context context;
  auto& process_context1 = SystemStateTracker::getProcessContext(
      context, *process_context_factory.get(), 1000);

  EXPECT_TRUE(process_context_factory->invocationCount() == 1U);
  EXPECT_EQ(context.process_map.size(), 1U);
  EXPECT_EQ(context.process_map.count(1000), 1U);

  EXPECT_EQ(context.process_map.at(1000).binary_path, "/usr/bin/zsh");

  EXPECT_EQ(&context.process_map.at(1000), &process_context1);

  SystemStateTracker::getProcessContext(
      context, *process_context_factory.get(), 1000);
  EXPECT_TRUE(process_context_factory->invocationCount() == 1U);

  process_context_factory->failNextRequest();
  auto& process_context2 = SystemStateTracker::getProcessContext(
      context, *process_context_factory.get(), 1001);

  EXPECT_TRUE(process_context_factory->invocationCount() == 1U);
  EXPECT_EQ(context.process_map.size(), 2U);
  EXPECT_EQ(context.process_map.count(1001), 1U);
  EXPECT_TRUE(context.process_map.at(1001).binary_path.empty());
  EXPECT_EQ(&context.process_map.at(1001), &process_context2);
}

TEST_F(SystemStateTrackerTests, create_process) {
  auto process_context_factory =
      std::make_unique<MockedProcessContextFactory>();

  // The fork/vfork/clone event, as received from BPF, is from the side of
  // the parent process, but the system tracker expects this to be on the
  // side of the child process (i.e.: clear exit_code and set process_id to
  // the child process identifier)
  auto bpf_event_header = kBaseBPFEventHeader;
  bpf_event_header.process_id = 1001;
  bpf_event_header.exit_code = 0;

  // We are starting with an empty process context map, so we are expecting:
  // 1. A call to the process context factory to create the parent process id
  // 2. Two different entries in the process map, one for the parent and one
  //    for the child process
  SystemStateTracker::Context context;
  auto succeeded = SystemStateTracker::createProcess(
      context,
      *process_context_factory.get(),
      bpf_event_header,
      1000, // parent pid
      bpf_event_header.process_id); // child pid

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(context.process_map.size(), 2U);
  EXPECT_EQ(process_context_factory->invocationCount(), 1U);

  EXPECT_EQ(context.process_map.count(1000), 1U);
  EXPECT_EQ(context.process_map.count(1001), 1U);

  const auto& parent_process1 = context.process_map.at(1000);
  EXPECT_EQ(parent_process1.parent_process_id, 2);

  const auto& child_process1 = context.process_map.at(1001);
  EXPECT_EQ(child_process1.parent_process_id, 1000);

  EXPECT_EQ(child_process1.binary_path, parent_process1.binary_path);
  EXPECT_EQ(child_process1.argv, parent_process1.argv);
  EXPECT_EQ(child_process1.cwd, parent_process1.cwd);
  EXPECT_EQ(child_process1.fd_map.size(), parent_process1.fd_map.size());

  // Make sure that the fork event was generated
  ASSERT_EQ(context.event_list.size(), 1U);

  const auto& fork_event1 = context.event_list.at(0U);
  EXPECT_EQ(fork_event1.type, ISystemStateTracker::Event::Type::Fork);
  EXPECT_EQ(fork_event1.parent_process_id, child_process1.parent_process_id);
  EXPECT_EQ(fork_event1.binary_path, child_process1.binary_path);
  EXPECT_EQ(fork_event1.cwd, child_process1.cwd);
  EXPECT_TRUE(std::holds_alternative<std::monostate>(fork_event1.data));

  // Create a new process again, from pid 1001. Since it's already tracked, we
  // are not expecting any new call to the factory
  bpf_event_header.process_id = 1002;
  bpf_event_header.exit_code = 0;

  succeeded = SystemStateTracker::createProcess(
      context,
      *process_context_factory.get(),
      bpf_event_header,
      1001, // parent pid
      bpf_event_header.process_id); // child pid

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(context.process_map.size(), 3U);
  EXPECT_EQ(process_context_factory->invocationCount(), 1U);

  EXPECT_EQ(context.process_map.count(1000), 1U);
  EXPECT_EQ(context.process_map.count(1001), 1U);
  EXPECT_EQ(context.process_map.count(1002), 1U);

  const auto& parent_process2 = context.process_map.at(1001);
  EXPECT_EQ(parent_process2.parent_process_id, 1000);

  const auto& child_process2 = context.process_map.at(1002);
  EXPECT_EQ(child_process2.parent_process_id, 1001);

  EXPECT_EQ(child_process2.binary_path, parent_process2.binary_path);
  EXPECT_EQ(child_process2.argv, parent_process2.argv);
  EXPECT_EQ(child_process2.cwd, parent_process2.cwd);
  EXPECT_EQ(child_process2.fd_map.size(), parent_process2.fd_map.size());

  // Make sure that the fork event was generated
  ASSERT_EQ(context.event_list.size(), 2U);

  const auto& fork_event2 = context.event_list.at(1U);
  EXPECT_EQ(fork_event2.type, ISystemStateTracker::Event::Type::Fork);
  EXPECT_EQ(fork_event2.parent_process_id, child_process2.parent_process_id);
  EXPECT_EQ(fork_event2.binary_path, child_process2.binary_path);
  EXPECT_EQ(fork_event2.cwd, child_process2.cwd);
  EXPECT_TRUE(std::holds_alternative<std::monostate>(fork_event2.data));
}

TEST_F(SystemStateTrackerTests, execute_binary_with_absolute_path) {
  auto bpf_event_header = kBaseBPFEventHeader;
  bpf_event_header.process_id = 1001;

  auto process_context_factory =
      std::make_unique<MockedProcessContextFactory>();

  SystemStateTracker::Context context;

  {
    ProcessContext process_context;
    process_context_factory->captureSingleProcess(process_context,
                                                  bpf_event_header.process_id);
    EXPECT_EQ(process_context_factory->invocationCount(), 1U);

    context.process_map.insert({bpf_event_header.process_id, process_context});
  }

  static const std::vector<std::string> kExecArgumentList = {"date", "--help"};
  auto succeeded =
      SystemStateTracker::executeBinary(context,
                                        *process_context_factory.get(),
                                        bpf_event_header,
                                        bpf_event_header.process_id,
                                        AT_FDCWD,
                                        0,
                                        "/usr/bin/date",
                                        kExecArgumentList);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(process_context_factory->invocationCount(), 1U);

  // Verify that:
  // 1. all the file descriptors marked as close-on-exec have been removed
  // 2. the binary path and argv in the process context entry have been updated
  EXPECT_EQ(context.process_map.size(), 1U);
  EXPECT_EQ(context.process_map.count(1001), 1U);

  const auto& process_context = context.process_map.at(1001);

  EXPECT_EQ(process_context.binary_path, "/usr/bin/date");
  EXPECT_EQ(process_context.argv, kExecArgumentList);
  EXPECT_EQ(process_context.fd_map.size(), 5U);

  // Make sure that the exec event was generated
  ASSERT_EQ(context.event_list.size(), 1U);

  const auto& exec_event = context.event_list.at(0U);
  EXPECT_EQ(exec_event.type, ISystemStateTracker::Event::Type::Exec);
  EXPECT_EQ(exec_event.parent_process_id, process_context.parent_process_id);
  EXPECT_EQ(exec_event.binary_path, process_context.binary_path);
  EXPECT_EQ(exec_event.cwd, process_context.cwd);

  ASSERT_TRUE(std::holds_alternative<ISystemStateTracker::Event::ExecData>(
      exec_event.data));

  const auto& exec_data =
      std::get<ISystemStateTracker::Event::ExecData>(exec_event.data);

  EXPECT_EQ(exec_data.argv, process_context.argv);
}

TEST_F(SystemStateTrackerTests, execute_binary_at_cwd) {
  auto bpf_event_header = kBaseBPFEventHeader;
  bpf_event_header.process_id = 1001;

  auto process_context_factory =
      std::make_unique<MockedProcessContextFactory>();

  SystemStateTracker::Context context;

  {
    ProcessContext process_context;
    process_context_factory->captureSingleProcess(process_context,
                                                  bpf_event_header.process_id);
    EXPECT_EQ(process_context_factory->invocationCount(), 1U);

    context.process_map.insert({bpf_event_header.process_id, process_context});
  }

  context.process_map[bpf_event_header.process_id].cwd = "/usr/bin";

  static const std::vector<std::string> kExecArgumentList = {"date", "--help"};
  auto succeeded =
      SystemStateTracker::executeBinary(context,
                                        *process_context_factory.get(),
                                        bpf_event_header,
                                        bpf_event_header.process_id,
                                        AT_FDCWD,
                                        0,
                                        "date",
                                        kExecArgumentList);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(process_context_factory->invocationCount(), 1U);

  // Verify that:
  // 1. all the file descriptors marked as close-on-exec have been removed
  // 2. the binary path and argv in the process context entry have been updated
  EXPECT_EQ(context.process_map.size(), 1U);
  EXPECT_EQ(context.process_map.count(1001), 1U);

  const auto& process_context = context.process_map.at(1001);

  EXPECT_EQ(process_context.binary_path, "/usr/bin/date");
  EXPECT_EQ(process_context.argv, kExecArgumentList);
  EXPECT_EQ(process_context.fd_map.size(), 5U);

  // Make sure that the exec event was generated
  ASSERT_EQ(context.event_list.size(), 1U);

  const auto& exec_event = context.event_list.at(0U);
  EXPECT_EQ(exec_event.type, ISystemStateTracker::Event::Type::Exec);
  EXPECT_EQ(exec_event.parent_process_id, process_context.parent_process_id);
  EXPECT_EQ(exec_event.binary_path, process_context.binary_path);
  EXPECT_EQ(exec_event.cwd, process_context.cwd);

  ASSERT_TRUE(std::holds_alternative<ISystemStateTracker::Event::ExecData>(
      exec_event.data));

  const auto& exec_data =
      std::get<ISystemStateTracker::Event::ExecData>(exec_event.data);

  EXPECT_EQ(exec_data.argv, process_context.argv);
}

TEST_F(SystemStateTrackerTests, execute_binary_with_fd) {
  auto bpf_event_header = kBaseBPFEventHeader;
  bpf_event_header.process_id = 1001;

  auto process_context_factory =
      std::make_unique<MockedProcessContextFactory>();

  SystemStateTracker::Context context;

  {
    ProcessContext process_context;
    process_context_factory->captureSingleProcess(process_context,
                                                  bpf_event_header.process_id);

    EXPECT_EQ(process_context_factory->invocationCount(), 1U);

    setFileDescriptor(process_context, 15, false, "/usr/bin/date");
    context.process_map.insert({bpf_event_header.process_id, process_context});
  }

  static const std::vector<std::string> kExecArgumentList = {"date", "--help"};

  // Attempt to execute the binary with both a path and the AT_EMPTY_PATH
  // flag specified. this should fail
  auto succeeded =
      SystemStateTracker::executeBinary(context,
                                        *process_context_factory.get(),
                                        bpf_event_header,
                                        bpf_event_header.process_id,
                                        15, // fd
                                        AT_EMPTY_PATH,
                                        "date",
                                        kExecArgumentList);

  EXPECT_FALSE(succeeded);

  // Try again to execute the binary, this time without the path
  succeeded = SystemStateTracker::executeBinary(context,
                                                *process_context_factory.get(),
                                                bpf_event_header,
                                                bpf_event_header.process_id,
                                                15, // fd
                                                AT_EMPTY_PATH,
                                                std::string(),
                                                kExecArgumentList);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(process_context_factory->invocationCount(), 1U);

  // Verify that:
  // 1. all the file descriptors marked as close-on-exec have been removed
  // 2. the binary path and argv in the process context entry have been updated
  EXPECT_EQ(context.process_map.size(), 1U);
  EXPECT_EQ(context.process_map.count(1001), 1U);

  const auto& process_context = context.process_map.at(1001);

  EXPECT_EQ(process_context.binary_path, "/usr/bin/date");
  EXPECT_EQ(process_context.argv, kExecArgumentList);
  EXPECT_EQ(process_context.fd_map.size(), 5U);

  // Make sure that the exec event was generated
  ASSERT_EQ(context.event_list.size(), 1U);

  const auto& exec_event = context.event_list.at(0U);
  EXPECT_EQ(exec_event.type, ISystemStateTracker::Event::Type::Exec);
  EXPECT_EQ(exec_event.parent_process_id, process_context.parent_process_id);
  EXPECT_EQ(exec_event.binary_path, process_context.binary_path);
  EXPECT_EQ(exec_event.cwd, process_context.cwd);

  ASSERT_TRUE(std::holds_alternative<ISystemStateTracker::Event::ExecData>(
      exec_event.data));

  const auto& exec_data =
      std::get<ISystemStateTracker::Event::ExecData>(exec_event.data);

  EXPECT_EQ(exec_data.argv, process_context.argv);
}

TEST_F(SystemStateTrackerTests, execute_binary_at_dirfd) {
  auto bpf_event_header = kBaseBPFEventHeader;
  bpf_event_header.process_id = 1001;

  auto process_context_factory =
      std::make_unique<MockedProcessContextFactory>();

  SystemStateTracker::Context context;

  {
    ProcessContext process_context;
    process_context_factory->captureSingleProcess(process_context,
                                                  bpf_event_header.process_id);

    EXPECT_EQ(process_context_factory->invocationCount(), 1U);

    setFileDescriptor(process_context, 15, false, "/usr/bin");
    context.process_map.insert({bpf_event_header.process_id, process_context});
  }

  static const std::vector<std::string> kExecArgumentList = {"date", "--help"};

  // Attempt to execute the binary with a missing FD
  auto succeeded =
      SystemStateTracker::executeBinary(context,
                                        *process_context_factory.get(),
                                        bpf_event_header,
                                        bpf_event_header.process_id,
                                        1000, // fd
                                        0,
                                        "date",
                                        kExecArgumentList);

  EXPECT_FALSE(succeeded);

  // Try again to execute the binary, this time with a valid dirfd value
  succeeded = SystemStateTracker::executeBinary(context,
                                                *process_context_factory.get(),
                                                bpf_event_header,
                                                bpf_event_header.process_id,
                                                15, // fd
                                                0,
                                                "date",
                                                kExecArgumentList);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(process_context_factory->invocationCount(), 1U);

  // Verify that:
  // 1. all the file descriptors marked as close-on-exec have been removed
  // 2. the binary path and argv in the process context entry have been updated
  EXPECT_EQ(context.process_map.size(), 1U);
  EXPECT_EQ(context.process_map.count(1001), 1U);

  const auto& process_context = context.process_map.at(1001);

  // The path we are expecting is: (process_context.fd_map.at(15).path) +
  // "/date"
  EXPECT_EQ(process_context.binary_path, "/usr/bin/date");
  EXPECT_EQ(process_context.argv, kExecArgumentList);
  EXPECT_EQ(process_context.fd_map.size(), 5U);

  // Make sure that the exec event was generated
  ASSERT_EQ(context.event_list.size(), 1U);

  const auto& exec_event = context.event_list.at(0U);
  EXPECT_EQ(exec_event.type, ISystemStateTracker::Event::Type::Exec);
  EXPECT_EQ(exec_event.parent_process_id, process_context.parent_process_id);
  EXPECT_EQ(exec_event.binary_path, process_context.binary_path);
  EXPECT_EQ(exec_event.cwd, process_context.cwd);

  ASSERT_TRUE(std::holds_alternative<ISystemStateTracker::Event::ExecData>(
      exec_event.data));

  const auto& exec_data =
      std::get<ISystemStateTracker::Event::ExecData>(exec_event.data);

  EXPECT_EQ(exec_data.argv, process_context.argv);
}

TEST_F(SystemStateTrackerTests, set_working_directory_with_path) {
  auto process_context_factory =
      std::make_unique<MockedProcessContextFactory>();

  SystemStateTracker::Context context;

  {
    ProcessContext process_context;
    process_context_factory->captureSingleProcess(
        process_context, kBaseBPFEventHeader.process_id);

    EXPECT_EQ(process_context_factory->invocationCount(), 1U);

    context.process_map.insert(
        {kBaseBPFEventHeader.process_id, process_context});
  }

  std::string test_cwd_folder{"/home/alessandro"};
  auto succeeded = SystemStateTracker::setWorkingDirectory(
      context, *process_context_factory.get(), 1001, test_cwd_folder);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(process_context_factory->invocationCount(), 1U);
  ASSERT_EQ(context.process_map.count(1001), 1U);

  const auto& process_context = context.process_map.at(1001);
  EXPECT_EQ(process_context.cwd, test_cwd_folder);
  EXPECT_TRUE(context.event_list.empty());
}

TEST_F(SystemStateTrackerTests, set_working_directory_with_fd) {
  auto process_context_factory =
      std::make_unique<MockedProcessContextFactory>();

  SystemStateTracker::Context context;
  std::string test_cwd_folder{"/home/alessandro"};

  {
    ProcessContext process_context;
    process_context_factory->captureSingleProcess(process_context, 1001);
    EXPECT_EQ(process_context_factory->invocationCount(), 1U);

    setFileDescriptor(process_context, 2000, true, test_cwd_folder);

    context.process_map.insert(
        {kBaseBPFEventHeader.process_id, process_context});
  }

  auto succeeded =
      SystemStateTracker::setWorkingDirectory(context,
                                              *process_context_factory.get(),
                                              kBaseBPFEventHeader.process_id,
                                              2000);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(process_context_factory->invocationCount(), 1U);
  ASSERT_EQ(context.process_map.count(kBaseBPFEventHeader.process_id), 1U);

  const auto& process_context =
      context.process_map.at(kBaseBPFEventHeader.process_id);

  EXPECT_EQ(process_context.cwd, test_cwd_folder);
  EXPECT_TRUE(context.event_list.empty());
}

TEST_F(SystemStateTrackerTests, close_handle) {
  auto process_context_factory =
      std::make_unique<MockedProcessContextFactory>();

  SystemStateTracker::Context context;
  std::string test_cwd_folder{"/home/alessandro"};

  {
    ProcessContext process_context;
    process_context_factory->captureSingleProcess(process_context, 1001);
    EXPECT_EQ(process_context_factory->invocationCount(), 1U);

    setFileDescriptor(process_context, 2000, true, test_cwd_folder);

    context.process_map.insert(
        {kBaseBPFEventHeader.process_id, process_context});
  }

  EXPECT_EQ(context.process_map[kBaseBPFEventHeader.process_id].fd_map.size(),
            9U);

  auto succeeded =
      SystemStateTracker::closeHandle(context,
                                      *process_context_factory.get(),
                                      kBaseBPFEventHeader.process_id,
                                      2000);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(process_context_factory->invocationCount(), 1U);
  ASSERT_EQ(context.process_map.count(kBaseBPFEventHeader.process_id), 1U);

  const auto& process_context =
      context.process_map.at(kBaseBPFEventHeader.process_id);

  EXPECT_EQ(process_context.fd_map.size(), 8U);
  EXPECT_EQ(process_context.fd_map.count(2000), 0U);

  EXPECT_TRUE(context.event_list.empty());
}

TEST_F(SystemStateTrackerTests, duplicate_handle) {
  SystemStateTracker::Context context;
  auto succeeded =
      SystemStateTracker::duplicateHandle(context, 1212, 1, 2, true);

  EXPECT_FALSE(succeeded);
  EXPECT_TRUE(context.process_map.empty());

  auto process_context_factory =
      std::make_unique<MockedProcessContextFactory>();

  {
    ProcessContext process_context;
    process_context_factory->captureSingleProcess(
        process_context, kBaseBPFEventHeader.process_id);

    EXPECT_EQ(process_context_factory->invocationCount(), 1U);

    context.process_map.insert(
        {kBaseBPFEventHeader.process_id, process_context});
  }

  auto& process_context =
      context.process_map.at(kBaseBPFEventHeader.process_id);

  succeeded = SystemStateTracker::duplicateHandle(
      context, kBaseBPFEventHeader.process_id, 1000, 3000, true);

  EXPECT_FALSE(succeeded);
  EXPECT_EQ(process_context.fd_map.size(), 8U);

  succeeded = SystemStateTracker::duplicateHandle(
      context, kBaseBPFEventHeader.process_id, 15, 16, true);

  EXPECT_TRUE(succeeded);
  ASSERT_EQ(context.process_map.count(kBaseBPFEventHeader.process_id), 1U);
  EXPECT_EQ(context.process_map.size(), 1U);
  EXPECT_EQ(process_context.fd_map.size(), 9U);

  EXPECT_TRUE(validateFileDescriptor(
      process_context, 15, false, "/usr/share/zsh/functions/Misc.zwc"));

  EXPECT_TRUE(validateFileDescriptor(
      process_context, 16, true, "/usr/share/zsh/functions/Misc.zwc"));

  EXPECT_TRUE(context.event_list.empty());
}

TEST_F(SystemStateTrackerTests, open_file) {
  SystemStateTracker::Context context;

  auto process_context_factory =
      std::make_unique<MockedProcessContextFactory>();

  {
    ProcessContext process_context;
    process_context_factory->captureSingleProcess(
        process_context, kBaseBPFEventHeader.process_id);
    EXPECT_EQ(process_context_factory->invocationCount(), 1U);

    context.process_map.insert(
        {kBaseBPFEventHeader.process_id, process_context});
  }

  auto& process_context =
      context.process_map.at(kBaseBPFEventHeader.process_id);

  EXPECT_EQ(process_context.fd_map.size(), 8U);

  // Empty file path
  auto succeeded = SystemStateTracker::openFile(context,
                                                *process_context_factory.get(),
                                                kBaseBPFEventHeader.process_id,
                                                AT_FDCWD,
                                                1000,
                                                "",
                                                0);

  EXPECT_FALSE(succeeded);
  EXPECT_EQ(process_context.fd_map.size(), 8U);
  EXPECT_EQ(process_context_factory->invocationCount(), 1U);

  // Invalid dirfd
  succeeded = SystemStateTracker::openFile(context,
                                           *process_context_factory.get(),
                                           kBaseBPFEventHeader.process_id,
                                           1000, // Invalid dirfd value
                                           16,
                                           "test_file",
                                           0);

  EXPECT_FALSE(succeeded);
  EXPECT_EQ(process_context.fd_map.size(), 8U);
  EXPECT_EQ(process_context_factory->invocationCount(), 1U);

  // Absolute paths, without close on exec
  std::string absolute_test_path{"/home/alessandro/Documents/secret.txt"};

  succeeded = SystemStateTracker::openFile(context,
                                           *process_context_factory.get(),
                                           kBaseBPFEventHeader.process_id,
                                           AT_FDCWD,
                                           16,
                                           absolute_test_path,
                                           0);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(process_context.fd_map.size(), 9U);
  EXPECT_TRUE(
      validateFileDescriptor(process_context, 16, false, absolute_test_path));
  EXPECT_EQ(process_context_factory->invocationCount(), 1U);

  // Absolute paths, with close on exec
  succeeded = SystemStateTracker::openFile(context,
                                           *process_context_factory.get(),
                                           kBaseBPFEventHeader.process_id,
                                           AT_FDCWD,
                                           17,
                                           absolute_test_path,
                                           O_CLOEXEC);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(process_context.fd_map.size(), 10U);
  EXPECT_TRUE(
      validateFileDescriptor(process_context, 17, true, absolute_test_path));
  EXPECT_EQ(process_context_factory->invocationCount(), 1U);

  // Relative paths + cwd, without close on exec
  std::string relative_test_path{"secret.txt"};

  succeeded = SystemStateTracker::openFile(context,
                                           *process_context_factory.get(),
                                           kBaseBPFEventHeader.process_id,
                                           AT_FDCWD,
                                           18,
                                           relative_test_path,
                                           0);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(process_context.fd_map.size(), 11U);
  EXPECT_TRUE(
      validateFileDescriptor(process_context,
                             18,
                             false,
                             process_context.cwd + "/" + relative_test_path));

  EXPECT_EQ(process_context_factory->invocationCount(), 1U);

  // Relative paths + cwd, with close on exec
  succeeded = SystemStateTracker::openFile(context,
                                           *process_context_factory.get(),
                                           kBaseBPFEventHeader.process_id,
                                           AT_FDCWD,
                                           19,
                                           relative_test_path,
                                           O_CLOEXEC);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(process_context.fd_map.size(), 12U);
  validateFileDescriptor(process_context,
                         19,
                         true,
                         process_context.cwd + "/" + relative_test_path);

  EXPECT_EQ(process_context_factory->invocationCount(), 1U);

  // Relative paths + dirfd, without close on exec
  std::string dirfd_folder_path{"/etc"};
  std::string dirfd_relative_path{"hosts"};

  setFileDescriptor(process_context, 20, true, dirfd_folder_path);

  succeeded = SystemStateTracker::openFile(context,
                                           *process_context_factory.get(),
                                           kBaseBPFEventHeader.process_id,
                                           20, // FD to the /etc folder
                                           21,
                                           dirfd_relative_path,
                                           0);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(process_context.fd_map.size(), 14U);
  EXPECT_TRUE(
      validateFileDescriptor(process_context,
                             21,
                             false,
                             dirfd_folder_path + "/" + dirfd_relative_path));

  EXPECT_EQ(process_context_factory->invocationCount(), 1U);

  // Relative paths + dirfd, with close on exec
  succeeded = SystemStateTracker::openFile(context,
                                           *process_context_factory.get(),
                                           kBaseBPFEventHeader.process_id,
                                           20, // FD to the /etc folder
                                           22,
                                           dirfd_relative_path,
                                           O_CLOEXEC);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(process_context.fd_map.size(), 15U);
  EXPECT_TRUE(
      validateFileDescriptor(process_context,
                             22,
                             true,
                             dirfd_folder_path + "/" + dirfd_relative_path));

  EXPECT_EQ(process_context_factory->invocationCount(), 1U);
}

TEST_F(SystemStateTrackerTests, create_socket) {
  SystemStateTracker::Context context;

  auto process_context_factory =
      std::make_unique<MockedProcessContextFactory>();

  {
    ProcessContext process_context;
    process_context_factory->captureSingleProcess(
        process_context, kBaseBPFEventHeader.process_id);

    EXPECT_EQ(process_context_factory->invocationCount(), 1U);

    context.process_map.insert(
        {kBaseBPFEventHeader.process_id, process_context});
  }

  auto& process_context =
      context.process_map.at(kBaseBPFEventHeader.process_id);

  EXPECT_EQ(process_context.fd_map.size(), 8U);

  auto succeeded =
      SystemStateTracker::createSocket(context,
                                       *process_context_factory.get(),
                                       kBaseBPFEventHeader.process_id,
                                       AF_INET6,
                                       SOCK_STREAM,
                                       0,
                                       99);

  EXPECT_EQ(process_context_factory->invocationCount(), 1U);

  ASSERT_TRUE(succeeded);

  ASSERT_EQ(process_context.fd_map.size(), 9U);
  ASSERT_EQ(process_context.fd_map.count(99), 1U);

  const auto& fd = process_context.fd_map.at(99);
  EXPECT_EQ(fd.close_on_exec, false);

  ASSERT_TRUE(
      std::holds_alternative<ProcessContext::FileDescriptor::SocketData>(
          fd.data));

  const auto& socket_data =
      std::get<ProcessContext::FileDescriptor::SocketData>(fd.data);

  ASSERT_TRUE(socket_data.opt_domain.has_value());
  ASSERT_TRUE(socket_data.opt_type.has_value());
  ASSERT_TRUE(socket_data.opt_protocol.has_value());

  EXPECT_EQ(socket_data.opt_domain.value(), AF_INET6);
  EXPECT_EQ(socket_data.opt_type.value(), SOCK_STREAM);
  EXPECT_EQ(socket_data.opt_protocol.value(), 0);
}

TEST_F(SystemStateTrackerTests, bind_socket) {
  SystemStateTracker::Context context;

  auto process_context_factory =
      std::make_unique<MockedProcessContextFactory>();

  {
    ProcessContext process_context;
    process_context_factory->captureSingleProcess(
        process_context, kBaseBPFEventHeader.process_id);

    EXPECT_EQ(process_context_factory->invocationCount(), 1U);

    context.process_map.insert(
        {kBaseBPFEventHeader.process_id, process_context});
  }

  auto& process_context =
      context.process_map.at(kBaseBPFEventHeader.process_id);

  setSocketDescriptor(
      process_context, 99, true, AF_UNIX, SOCK_STREAM, 0, "", 1, "", 1);

  EXPECT_EQ(process_context.fd_map.size(), 9U);

  auto succeeded = SystemStateTracker::bind(context,
                                            *process_context_factory.get(),
                                            kBaseBPFEventHeader,
                                            kBaseBPFEventHeader.process_id,
                                            99,
                                            kTestUnixSocketAddress);

  EXPECT_EQ(process_context_factory->invocationCount(), 1U);
  ASSERT_TRUE(succeeded);

  ASSERT_EQ(process_context.fd_map.size(), 9U);
  ASSERT_EQ(process_context.fd_map.count(99), 1U);

  const auto& fd = process_context.fd_map.at(99);
  EXPECT_EQ(fd.close_on_exec, true);

  ASSERT_TRUE(
      std::holds_alternative<ProcessContext::FileDescriptor::SocketData>(
          fd.data));

  const auto& socket_data =
      std::get<ProcessContext::FileDescriptor::SocketData>(fd.data);

  ASSERT_TRUE(socket_data.opt_local_address.has_value());
  ASSERT_TRUE(socket_data.opt_local_port.has_value());

  ASSERT_EQ(socket_data.opt_local_address.value(), "/test/path");
  ASSERT_EQ(socket_data.opt_local_port.value(), 0);

  // Make sure that the bind event was generated
  ASSERT_EQ(context.event_list.size(), 1U);

  const auto& bind_event = context.event_list.at(0U);
  EXPECT_EQ(bind_event.type, ISystemStateTracker::Event::Type::Bind);
  ASSERT_TRUE(std::holds_alternative<ISystemStateTracker::Event::SocketData>(
      bind_event.data));

  const auto& event_data =
      std::get<ISystemStateTracker::Event::SocketData>(bind_event.data);

  EXPECT_EQ(event_data.domain, AF_UNIX);
  EXPECT_EQ(event_data.type, SOCK_STREAM);
  EXPECT_EQ(event_data.protocol, 0);
  EXPECT_EQ(event_data.fd, 99);
  EXPECT_EQ(event_data.local_address, "/test/path");
  EXPECT_EQ(event_data.local_port, 0);
  EXPECT_TRUE(event_data.remote_address.empty());
  EXPECT_EQ(event_data.remote_port, 1);
}

TEST_F(SystemStateTrackerTests, listen_socket) {
  SystemStateTracker::Context context;

  auto process_context_factory =
      std::make_unique<MockedProcessContextFactory>();

  {
    ProcessContext process_context;
    process_context_factory->captureSingleProcess(
        process_context, kBaseBPFEventHeader.process_id);

    EXPECT_EQ(process_context_factory->invocationCount(), 1U);

    context.process_map.insert(
        {kBaseBPFEventHeader.process_id, process_context});
  }

  auto& process_context =
      context.process_map.at(kBaseBPFEventHeader.process_id);

  setSocketDescriptor(process_context,
                      99,
                      true,
                      AF_INET,
                      SOCK_STREAM,
                      0,
                      "127.0.0.1",
                      8080,
                      "",
                      0);

  EXPECT_EQ(process_context.fd_map.size(), 9U);

  auto succeeded = SystemStateTracker::listen(context,
                                              *process_context_factory.get(),
                                              kBaseBPFEventHeader,
                                              kBaseBPFEventHeader.process_id,
                                              99);

  EXPECT_EQ(process_context_factory->invocationCount(), 1U);
  ASSERT_TRUE(succeeded);

  ASSERT_EQ(process_context.fd_map.size(), 9U);

  // Make sure that the bind event was generated
  ASSERT_EQ(context.event_list.size(), 1U);

  const auto& listen_event = context.event_list.at(0U);
  EXPECT_EQ(listen_event.type, ISystemStateTracker::Event::Type::Listen);
  ASSERT_TRUE(std::holds_alternative<ISystemStateTracker::Event::SocketData>(
      listen_event.data));

  const auto& event_data =
      std::get<ISystemStateTracker::Event::SocketData>(listen_event.data);

  EXPECT_EQ(event_data.domain, AF_INET);
  EXPECT_EQ(event_data.type, SOCK_STREAM);
  EXPECT_EQ(event_data.protocol, 0);
  EXPECT_EQ(event_data.fd, 99);
  EXPECT_EQ(event_data.local_address, "127.0.0.1");
  EXPECT_EQ(event_data.local_port, 8080);
  EXPECT_TRUE(event_data.remote_address.empty());
  EXPECT_EQ(event_data.remote_port, 0);
}

TEST_F(SystemStateTrackerTests, connect_socket) {
  SystemStateTracker::Context context;

  auto process_context_factory =
      std::make_unique<MockedProcessContextFactory>();

  {
    ProcessContext process_context;
    process_context_factory->captureSingleProcess(
        process_context, kBaseBPFEventHeader.process_id);

    EXPECT_EQ(process_context_factory->invocationCount(), 1U);

    context.process_map.insert(
        {kBaseBPFEventHeader.process_id, process_context});
  }

  auto& process_context =
      context.process_map.at(kBaseBPFEventHeader.process_id);

  setSocketDescriptor(process_context,
                      99,
                      true,
                      AF_INET,
                      SOCK_STREAM,
                      0,
                      "127.0.0.1",
                      8080,
                      "",
                      0);

  EXPECT_EQ(process_context.fd_map.size(), 9U);

  auto succeeded = SystemStateTracker::connect(context,
                                               *process_context_factory.get(),
                                               kBaseBPFEventHeader,
                                               kBaseBPFEventHeader.process_id,
                                               99,
                                               kTestIPv4Address);

  EXPECT_EQ(process_context_factory->invocationCount(), 1U);
  ASSERT_TRUE(succeeded);

  ASSERT_EQ(process_context.fd_map.size(), 9U);

  // Make sure that the bind event was generated
  ASSERT_EQ(context.event_list.size(), 1U);

  const auto& connect_event = context.event_list.at(0U);
  EXPECT_EQ(connect_event.type, ISystemStateTracker::Event::Type::Connect);
  ASSERT_TRUE(std::holds_alternative<ISystemStateTracker::Event::SocketData>(
      connect_event.data));

  const auto& event_data =
      std::get<ISystemStateTracker::Event::SocketData>(connect_event.data);

  EXPECT_EQ(event_data.domain, AF_INET);
  EXPECT_EQ(event_data.type, SOCK_STREAM);
  EXPECT_EQ(event_data.protocol, 0);
  EXPECT_EQ(event_data.fd, 99);
  EXPECT_EQ(event_data.local_address, "127.0.0.1");
  EXPECT_EQ(event_data.local_port, 8080);
  EXPECT_EQ(event_data.remote_address, "192.168.1.2");
  EXPECT_EQ(event_data.remote_port, 80);
}

TEST_F(SystemStateTrackerTests, accept_socket) {
  SystemStateTracker::Context context;

  auto process_context_factory =
      std::make_unique<MockedProcessContextFactory>();

  {
    ProcessContext process_context;
    process_context_factory->captureSingleProcess(
        process_context, kBaseBPFEventHeader.process_id);

    EXPECT_EQ(process_context_factory->invocationCount(), 1U);

    context.process_map.insert(
        {kBaseBPFEventHeader.process_id, process_context});
  }

  auto& process_context =
      context.process_map.at(kBaseBPFEventHeader.process_id);

  setSocketDescriptor(process_context,
                      99,
                      true,
                      AF_INET,
                      SOCK_STREAM,
                      0,
                      "127.0.0.1",
                      8080,
                      "",
                      0);

  EXPECT_EQ(process_context.fd_map.size(), 9U);

  // Accept two new connections; for one of them, try to use the
  // SOCK_CLOEXEC flag to automatically set the close_on_exec
  // option
  auto succeeded = SystemStateTracker::accept(context,
                                              *process_context_factory.get(),
                                              kBaseBPFEventHeader,
                                              kBaseBPFEventHeader.process_id,
                                              99,
                                              kTestIPv4Address,
                                              100,
                                              0);

  EXPECT_EQ(process_context_factory->invocationCount(), 1U);
  EXPECT_EQ(process_context.fd_map.size(), 10U);
  ASSERT_TRUE(succeeded);

  succeeded = SystemStateTracker::accept(context,
                                         *process_context_factory.get(),
                                         kBaseBPFEventHeader,
                                         kBaseBPFEventHeader.process_id,
                                         99,
                                         kTestIPv4Address,
                                         101,
                                         SOCK_CLOEXEC);

  EXPECT_EQ(process_context_factory->invocationCount(), 1U);
  EXPECT_EQ(process_context.fd_map.size(), 11U);
  ASSERT_TRUE(succeeded);

  // There should be 2 new file descriptors
  ASSERT_EQ(process_context.fd_map.count(100), 1U);
  ASSERT_EQ(process_context.fd_map.count(101), 1U);

  const auto& fd1 = process_context.fd_map.at(100);
  EXPECT_FALSE(fd1.close_on_exec);

  ASSERT_TRUE(
      std::holds_alternative<ProcessContext::FileDescriptor::SocketData>(
          fd1.data));

  const auto& socket_data1 =
      std::get<ProcessContext::FileDescriptor::SocketData>(fd1.data);

  ASSERT_TRUE(socket_data1.opt_domain.has_value());
  ASSERT_TRUE(socket_data1.opt_type.has_value());
  ASSERT_TRUE(socket_data1.opt_protocol.has_value());
  ASSERT_TRUE(socket_data1.opt_local_address.has_value());
  ASSERT_TRUE(socket_data1.opt_local_port.has_value());
  ASSERT_TRUE(socket_data1.opt_remote_address.has_value());
  ASSERT_TRUE(socket_data1.opt_remote_port.has_value());

  EXPECT_EQ(socket_data1.opt_domain.value(), AF_INET);
  EXPECT_EQ(socket_data1.opt_type.value(), SOCK_STREAM);
  EXPECT_EQ(socket_data1.opt_protocol.value(), 0);
  EXPECT_EQ(socket_data1.opt_local_address.value(), "127.0.0.1");
  EXPECT_EQ(socket_data1.opt_local_port.value(), 8080);
  EXPECT_EQ(socket_data1.opt_remote_address.value(), "192.168.1.2");
  EXPECT_EQ(socket_data1.opt_remote_port.value(), 80);

  const auto& fd2 = process_context.fd_map.at(101);
  EXPECT_TRUE(fd2.close_on_exec);

  ASSERT_TRUE(
      std::holds_alternative<ProcessContext::FileDescriptor::SocketData>(
          fd2.data));

  const auto& socket_data2 =
      std::get<ProcessContext::FileDescriptor::SocketData>(fd2.data);

  ASSERT_TRUE(socket_data2.opt_domain.has_value());
  ASSERT_TRUE(socket_data2.opt_type.has_value());
  ASSERT_TRUE(socket_data2.opt_protocol.has_value());
  ASSERT_TRUE(socket_data2.opt_local_address.has_value());
  ASSERT_TRUE(socket_data2.opt_local_port.has_value());
  ASSERT_TRUE(socket_data2.opt_remote_address.has_value());
  ASSERT_TRUE(socket_data2.opt_remote_port.has_value());

  EXPECT_EQ(socket_data2.opt_domain.value(), AF_INET);
  EXPECT_EQ(socket_data2.opt_type.value(), SOCK_STREAM);
  EXPECT_EQ(socket_data2.opt_protocol.value(), 0);
  EXPECT_EQ(socket_data2.opt_local_address.value(), "127.0.0.1");
  EXPECT_EQ(socket_data2.opt_local_port.value(), 8080);
  EXPECT_EQ(socket_data2.opt_remote_address.value(), "192.168.1.2");
  EXPECT_EQ(socket_data2.opt_remote_port.value(), 80);

  // We should now have two identical events
  ASSERT_EQ(context.event_list.size(), 2U);

  const auto& accept_event1 = context.event_list.at(0U);
  EXPECT_EQ(accept_event1.type, ISystemStateTracker::Event::Type::Accept);

  const auto& accept_event2 = context.event_list.at(1U);
  EXPECT_EQ(accept_event2.type, ISystemStateTracker::Event::Type::Accept);

  ASSERT_TRUE(std::holds_alternative<ISystemStateTracker::Event::SocketData>(
      accept_event1.data));

  ASSERT_TRUE(std::holds_alternative<ISystemStateTracker::Event::SocketData>(
      accept_event2.data));

  const auto& event_data1 =
      std::get<ISystemStateTracker::Event::SocketData>(accept_event1.data);

  const auto& event_data2 =
      std::get<ISystemStateTracker::Event::SocketData>(accept_event2.data);

  EXPECT_EQ(event_data1.domain, AF_INET);
  EXPECT_EQ(event_data1.type, SOCK_STREAM);
  EXPECT_EQ(event_data1.protocol, 0);
  EXPECT_EQ(event_data1.fd, 100);
  EXPECT_EQ(event_data1.local_address, "127.0.0.1");
  EXPECT_EQ(event_data1.local_port, 8080);
  EXPECT_EQ(event_data1.remote_address, "192.168.1.2");
  EXPECT_EQ(event_data1.remote_port, 80);

  EXPECT_EQ(event_data2.domain, AF_INET);
  EXPECT_EQ(event_data2.type, SOCK_STREAM);
  EXPECT_EQ(event_data2.protocol, 0);
  EXPECT_EQ(event_data2.fd, 101);
  EXPECT_EQ(event_data2.local_address, "127.0.0.1");
  EXPECT_EQ(event_data2.local_port, 8080);
  EXPECT_EQ(event_data2.remote_address, "192.168.1.2");
  EXPECT_EQ(event_data2.remote_port, 80);
}

TEST_F(SystemStateTrackerTests, parse_ipv4_sockaddr) {
  std::string address;
  std::uint16_t port{};
  auto succeeded =
      SystemStateTracker::parseInetSockaddr(address, port, kTestIPv4Address);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(address, "192.168.1.2");
  EXPECT_EQ(port, 80);
}

TEST_F(SystemStateTrackerTests, parse_ipv6_sockaddr) {
  struct TestCase final {
    std::vector<std::uint8_t> sockaddr_in6;
    std::string expected_address;
  };

  // clang-format off
  static const std::vector<TestCase> kTestCaseList = {
    {
      kTestIPv6Address,
      "1:203:405:607:809:a0b:c0d:e0f"
    },

    {
      {
        0x0a, 0x00, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x00,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xfc, 0x54, 0x00, 0x00, 0x00, 0x00, 0xd4, 0xf4,
        0x00, 0x00, 0x00, 0x00
      },

      "fe80::fc54:0:0:d4f4"
    },

    {
      {
        0x0a, 0x00, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x00,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x54,
        0xfc, 0x54, 0x00, 0x00, 0x00, 0x00, 0xd4, 0xf4,
        0x00, 0x00, 0x00, 0x00
      },

      "fe80::fc54:fc54:0:0:d4f4"
    },

    {
      {
        0x0a, 0x00, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x00,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x54,
        0xfc, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
      },

      "fe80:0:0:fc54:fc54::"
    },

    {
      {
        0x0a, 0x00, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00
      },

      "::1"
    },

    {
      {
        0x0a, 0x00, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
      },

      "1::"
    },
  };
  // clang-format on

  for (const auto& test_case : kTestCaseList) {
    std::string address;
    std::uint16_t port{};
    auto succeeded = SystemStateTracker::parseInet6Sockaddr(
        address, port, test_case.sockaddr_in6);

    EXPECT_TRUE(succeeded);
    EXPECT_EQ(address, test_case.expected_address);
    EXPECT_EQ(port, 8080);
  }
}

TEST_F(SystemStateTrackerTests, parse_unix_sockaddr) {
  std::string address;
  auto succeeded =
      SystemStateTracker::parseUnixSockaddr(address, kTestUnixSocketAddress);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(address, "/test/path");
}

TEST_F(SystemStateTrackerTests, parse_netlink_sockaddr) {
  std::string address;
  std::uint16_t port;

  auto succeeded = SystemStateTracker::parseNetlinkSockaddr(
      address, port, kTestNetlinkSockaddr);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(address, "1");
  EXPECT_EQ(port, 2);
}

TEST_F(SystemStateTrackerTests, createFileHandleIndex) {
  auto index =
      SystemStateTracker::createFileHandleIndex(0x15, {0xAA, 0xBB, 0xCC, 0xDD});

  EXPECT_EQ(index, "00000015_aabbccdd");
}

TEST_F(SystemStateTrackerTests, saveFileHandle) {
  const int dfd{0x10};
  const std::string name{"testtest"};
  const int handle_type{0x20};
  const std::vector<std::uint8_t> handle{0x01, 0x02, 0x03};
  const int mnt_id{200};
  const int flag{};

  // Add the file struct
  SystemStateTracker::Context context;
  SystemStateTracker::saveFileHandle(
      context, dfd, name, handle_type, handle, mnt_id, flag);

  EXPECT_EQ(context.file_handle_struct_map.size(), 1U);
  EXPECT_EQ(context.file_handle_struct_index.size(), 1U);

  // Attempt to add it again; this should be ignored
  SystemStateTracker::saveFileHandle(
      context, dfd, name, handle_type, handle, mnt_id, flag);

  EXPECT_EQ(context.file_handle_struct_map.size(), 1U);
  EXPECT_EQ(context.file_handle_struct_index.size(), 1U);

  // Validate that the index was added correctly
  auto index = SystemStateTracker::createFileHandleIndex(handle_type, handle);

  EXPECT_EQ(context.file_handle_struct_map.count(index), 1U);
  EXPECT_EQ(context.file_handle_struct_index.size(), 1U);

  // Make sure that the handle was saved correctly
  auto first_item_it = context.file_handle_struct_map.begin();
  const auto& file_handle_struct = first_item_it->second;

  EXPECT_EQ(file_handle_struct.dfd, dfd);
  EXPECT_EQ(file_handle_struct.name, name);
  EXPECT_EQ(file_handle_struct.flags, flag);
}

TEST_F(SystemStateTrackerTests, expireFileHandleEntries) {
  SystemStateTracker::Context context;
  SystemStateTracker::saveFileHandle(context, 1, "test1", 1, {1}, 1, 0);
  SystemStateTracker::saveFileHandle(context, 2, "test2", 2, {2}, 2, 0);
  SystemStateTracker::saveFileHandle(context, 3, "test3", 3, {3}, 3, 0);
  SystemStateTracker::saveFileHandle(context, 4, "test4", 4, {4}, 4, 0);

  EXPECT_EQ(context.file_handle_struct_map.size(), 4U);
  EXPECT_EQ(context.file_handle_struct_index.size(), 4U);

  SystemStateTracker::expireFileHandleEntries(context, 0U);
  EXPECT_EQ(context.file_handle_struct_map.size(), 4U);
  EXPECT_EQ(context.file_handle_struct_index.size(), 4U);

  SystemStateTracker::expireFileHandleEntries(context, 10U);
  EXPECT_EQ(context.file_handle_struct_map.size(), 4U);
  EXPECT_EQ(context.file_handle_struct_index.size(), 4U);

  SystemStateTracker::expireFileHandleEntries(context, 5U);
  EXPECT_EQ(context.file_handle_struct_map.size(), 4U);
  EXPECT_EQ(context.file_handle_struct_index.size(), 4U);

  SystemStateTracker::expireFileHandleEntries(context, 4U);
  EXPECT_EQ(context.file_handle_struct_map.size(), 4U);
  EXPECT_EQ(context.file_handle_struct_index.size(), 4U);

  SystemStateTracker::expireFileHandleEntries(context, 3U);
  EXPECT_EQ(context.file_handle_struct_map.size(), 3U);
  EXPECT_EQ(context.file_handle_struct_index.size(), 3U);

  SystemStateTracker::expireFileHandleEntries(context, 2U);
  EXPECT_EQ(context.file_handle_struct_map.size(), 2U);
  EXPECT_EQ(context.file_handle_struct_index.size(), 2U);

  SystemStateTracker::expireFileHandleEntries(context, 1U);
  EXPECT_EQ(context.file_handle_struct_map.size(), 1U);
  EXPECT_EQ(context.file_handle_struct_index.size(), 1U);
}

TEST_F(SystemStateTrackerTests, expireProcessContexts) {
  SystemStateTracker::Context context;

  context.process_map.insert(
      {kBaseBPFEventHeader.process_id, ProcessContext{}});

  context.process_map.insert(
      {kBaseBPFEventHeader.process_id + 1, ProcessContext{}});

  context.process_map.insert(
      {kBaseBPFEventHeader.process_id + 2, ProcessContext{}});

  MockedFilesystem mocked_filesystem;
  EXPECT_EQ(context.process_map.size(), 3U);

  SystemStateTracker::expireProcessContexts(context, mocked_filesystem);
  EXPECT_EQ(context.process_map.size(), 1U);
}

TEST_F(SystemStateTrackerTests, parseSocketAddress) {
  static const std::uint16_t kUnspecFamily{AF_UNSPEC};

  struct TestCase final {
    const std::vector<std::uint8_t>& sockaddr_buffer;
    std::string expected_address{};
    std::uint16_t expected_port{};
    int domain{};
  };

  static const std::vector<TestCase> kTestCaseList = {
      {
          std::ref(kTestIPv4Address),
          "192.168.1.2",
          80,
          AF_INET,
      },

      {
          std::ref(kTestIPv6Address),
          "1:203:405:607:809:a0b:c0d:e0f",
          8080,
          AF_INET6,
      },

      {
          std::ref(kTestNetlinkSockaddr),
          "1",
          2,
          AF_NETLINK,
      },

      {
          std::ref(kTestUnixSocketAddress),
          "/test/path",
          0,
          AF_UNIX,
      },
  };

  ProcessContext::FileDescriptor::SocketData socket_data;

  for (const auto& initialize_opt_domain : {0, 1, 2}) {
    for (const auto& clear_sockaddr_family : {false, true}) {
      for (const auto& use_local_address : {false, true}) {
        for (const auto& test_case : kTestCaseList) {
          socket_data = {};

          if (initialize_opt_domain == 0) {
            socket_data.opt_domain = std::nullopt;

          } else if (initialize_opt_domain == 1) {
            socket_data.opt_domain = AF_UNSPEC;

          } else if (initialize_opt_domain == 2) {
            socket_data.opt_domain = test_case.domain;

          } else {
            throw std::logic_error("Invalid initialize_opt_domain value");
          }

          auto sockaddr = test_case.sockaddr_buffer;
          if (clear_sockaddr_family == 1) {
            std::memcpy(sockaddr.data(), &kUnspecFamily, sizeof(kUnspecFamily));
          }

          ASSERT_TRUE(SystemStateTracker::parseSocketAddress(
              socket_data, sockaddr, use_local_address));

          ASSERT_EQ(socket_data.opt_local_address.has_value(),
                    use_local_address);

          ASSERT_EQ(socket_data.opt_local_port.has_value(), use_local_address);

          ASSERT_EQ(socket_data.opt_remote_address.has_value(),
                    !use_local_address);

          ASSERT_EQ(socket_data.opt_remote_port.has_value(),
                    !use_local_address);

          const auto& address_value =
              use_local_address ? socket_data.opt_local_address.value()
                                : socket_data.opt_remote_address.value();

          const auto& port_value = use_local_address
                                       ? socket_data.opt_local_port.value()
                                       : socket_data.opt_remote_port.value();

          EXPECT_EQ(address_value, test_case.expected_address);
          EXPECT_EQ(port_value, test_case.expected_port);
        }
      }
    }
  }
}

} // namespace osquery
