/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "bpftestsmain.h"
#include "mockedprocesscontextfactory.h"
#include "utils.h"

#include <osquery/events/linux/bpf/systemstatetracker.h>

#include <linux/fcntl.h>

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
} // namespace osquery
