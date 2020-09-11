/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iostream>

#include "bpftestsmain.h"

#include <osquery/events/linux/bpf/systemstatetracker.h>

#include <linux/fcntl.h>

namespace osquery {
namespace {
// clang-format off
const tob::ebpfpub::IFunctionTracer::Event::Header kBaseBPFEventHeader {
  // nsecs timestamp, starting from the system boot
  0U,

  // thread id
  100,

  // process id
  100,

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

// clang-format off
const ProcessContext kBaseProcessContext{
  // parent process id
  1000,

  // binary path
  "/bin/bash",

  // argv
  { "bash", "arg1", "arg2" },

  // current working directory
  "/root",

  // file descriptor map
  {
    {
      // file descriptor
      1,

      {
        // path
        "/bin/zsh",

        // close on exec
        false
      }
    },

    {
      // file descriptor
      2,

      {
        // path
        "/etc/hostname",

        // close on exec
        true
      }
    }
  }
};
// clang-format on
} // namespace

TEST_F(SystemStateTrackerTests, getProcessContext) {
  bool process_context_created{false};
  bool fail_process_context_creation{false};

  auto L_processContextFactory =
      [&process_context_created, &fail_process_context_creation](
          ProcessContext& process_context, pid_t process_id) -> bool {
    process_context = {};
    if (fail_process_context_creation) {
      return false;
    }

    process_context_created = true;
    process_context = kBaseProcessContext;

    return true;
  };

  SystemStateTracker::Context context;
  auto& process_context1 = SystemStateTracker::getProcessContext(
      context, L_processContextFactory, 1000);

  EXPECT_TRUE(process_context_created);
  EXPECT_EQ(context.process_map.size(), 1U);
  EXPECT_EQ(context.process_map.count(1000), 1U);

  EXPECT_EQ(context.process_map.at(1000).binary_path,
            kBaseProcessContext.binary_path);

  EXPECT_EQ(&context.process_map.at(1000), &process_context1);

  process_context_created = false;
  SystemStateTracker::getProcessContext(context, L_processContextFactory, 1000);
  EXPECT_FALSE(process_context_created);

  process_context_created = false;
  fail_process_context_creation = true;
  auto& process_context2 = SystemStateTracker::getProcessContext(
      context, L_processContextFactory, 1001);

  EXPECT_FALSE(process_context_created);
  EXPECT_EQ(context.process_map.size(), 2U);
  EXPECT_EQ(context.process_map.count(1001), 1U);
  EXPECT_TRUE(context.process_map.at(1001).binary_path.empty());
  EXPECT_EQ(&context.process_map.at(1001), &process_context2);
}

TEST_F(SystemStateTrackerTests, create_process) {
  std::size_t factory_call_count{0U};

  auto L_processContextFactory = [&factory_call_count](
                                     ProcessContext& process_context,
                                     pid_t process_id) -> bool {
    process_context = kBaseProcessContext;

    if (process_id == 1000) {
      process_context.parent_process_id = 1;

    } else if (process_id == 1001) {
      process_context.parent_process_id = 1000;
    }

    ++factory_call_count;
    return true;
  };

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
      L_processContextFactory,
      bpf_event_header,
      1000, // parent pid
      bpf_event_header.process_id); // child pid

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(context.process_map.size(), 2U);
  EXPECT_EQ(factory_call_count, 1U);

  EXPECT_EQ(context.process_map.count(1000), 1U);
  EXPECT_EQ(context.process_map.count(1001), 1U);

  const auto& parent_process1 = context.process_map.at(1000);
  EXPECT_EQ(parent_process1.parent_process_id, 1);

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
      L_processContextFactory,
      bpf_event_header,
      1001, // parent pid
      bpf_event_header.process_id); // child pid

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(context.process_map.size(), 3U);
  EXPECT_EQ(factory_call_count, 1U);

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
  std::size_t factory_call_count{0U};

  auto L_processContextFactory = [&factory_call_count](ProcessContext&,
                                                       pid_t) -> bool {
    ++factory_call_count;
    return false;
  };

  auto bpf_event_header = kBaseBPFEventHeader;
  bpf_event_header.process_id = 1001;

  SystemStateTracker::Context context;
  context.process_map.insert(
      {bpf_event_header.process_id, kBaseProcessContext});

  static const std::vector<std::string> kExecArgumentList = {"zsh"};
  auto succeeded =
      SystemStateTracker::executeBinary(context,
                                        L_processContextFactory,
                                        bpf_event_header,
                                        bpf_event_header.process_id,
                                        AT_FDCWD,
                                        0,
                                        "/bin/zsh",
                                        kExecArgumentList);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(factory_call_count, 0U);

  // Verify that:
  // 1. all the file descriptors marked as close-on-exec have been removed
  // 2. the binary path and argv in the process context entry have been updated
  EXPECT_EQ(context.process_map.size(), 1U);
  EXPECT_EQ(context.process_map.count(1001), 1U);

  const auto& process_context = context.process_map.at(1001);

  EXPECT_EQ(process_context.binary_path, "/bin/zsh");
  EXPECT_EQ(process_context.argv, kExecArgumentList);
  EXPECT_EQ(process_context.fd_map.size(), 1U);

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
  std::size_t factory_call_count{0U};

  auto L_processContextFactory = [&factory_call_count](ProcessContext&,
                                                       pid_t) -> bool {
    ++factory_call_count;
    return false;
  };

  auto bpf_event_header = kBaseBPFEventHeader;
  bpf_event_header.process_id = 1001;

  SystemStateTracker::Context context;
  context.process_map.insert(
      {bpf_event_header.process_id, kBaseProcessContext});

  context.process_map[bpf_event_header.process_id].cwd = "/bin";

  static const std::vector<std::string> kExecArgumentList = {"zsh"};
  auto succeeded =
      SystemStateTracker::executeBinary(context,
                                        L_processContextFactory,
                                        bpf_event_header,
                                        bpf_event_header.process_id,
                                        AT_FDCWD,
                                        0,
                                        "zsh",
                                        kExecArgumentList);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(factory_call_count, 0U);

  // Verify that:
  // 1. all the file descriptors marked as close-on-exec have been removed
  // 2. the binary path and argv in the process context entry have been updated
  EXPECT_EQ(context.process_map.size(), 1U);
  EXPECT_EQ(context.process_map.count(1001), 1U);

  const auto& process_context = context.process_map.at(1001);

  EXPECT_EQ(process_context.binary_path, "/bin/zsh");
  EXPECT_EQ(process_context.argv, kExecArgumentList);
  EXPECT_EQ(process_context.fd_map.size(), 1U);

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
  std::size_t factory_call_count{0U};

  auto L_processContextFactory = [&factory_call_count](ProcessContext&,
                                                       pid_t) -> bool {
    ++factory_call_count;
    return false;
  };

  auto bpf_event_header = kBaseBPFEventHeader;
  bpf_event_header.process_id = 1001;

  SystemStateTracker::Context context;
  context.process_map.insert(
      {bpf_event_header.process_id, kBaseProcessContext});

  static const std::vector<std::string> kExecArgumentList = {"zsh"};

  // Attempt to execute the binary with both a path and the AT_EMPTY_PATH
  // flag specified. this should fail
  auto succeeded = SystemStateTracker::executeBinary(
      context,
      L_processContextFactory,
      bpf_event_header,
      bpf_event_header.process_id,
      1, // This FD maps to /bin/zsh in the process context
      AT_EMPTY_PATH,
      "zsh",
      kExecArgumentList);

  EXPECT_FALSE(succeeded);

  // Try again to execute the binary, this time without the path
  succeeded = SystemStateTracker::executeBinary(
      context,
      L_processContextFactory,
      bpf_event_header,
      bpf_event_header.process_id,
      1, // This FD maps to /bin/zsh in the process context
      AT_EMPTY_PATH,
      std::string(),
      kExecArgumentList);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(factory_call_count, 0U);

  // Verify that:
  // 1. all the file descriptors marked as close-on-exec have been removed
  // 2. the binary path and argv in the process context entry have been updated
  EXPECT_EQ(context.process_map.size(), 1U);
  EXPECT_EQ(context.process_map.count(1001), 1U);

  const auto& process_context = context.process_map.at(1001);

  EXPECT_EQ(process_context.binary_path, "/bin/zsh");
  EXPECT_EQ(process_context.argv, kExecArgumentList);
  EXPECT_EQ(process_context.fd_map.size(), 1U);

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
  std::size_t factory_call_count{0U};

  auto L_processContextFactory = [&factory_call_count](ProcessContext&,
                                                       pid_t) -> bool {
    ++factory_call_count;
    return false;
  };

  auto bpf_event_header = kBaseBPFEventHeader;
  bpf_event_header.process_id = 1001;

  SystemStateTracker::Context context;
  context.process_map.insert(
      {bpf_event_header.process_id, kBaseProcessContext});

  static const std::vector<std::string> kExecArgumentList = {"zsh"};

  // Attempt to execute the binary with a missing FD
  auto succeeded =
      SystemStateTracker::executeBinary(context,
                                        L_processContextFactory,
                                        bpf_event_header,
                                        bpf_event_header.process_id,
                                        1000, // This FD value does not exist
                                        0,
                                        "zsh",
                                        kExecArgumentList);

  EXPECT_FALSE(succeeded);

  // Try again to execute the binary, this time with a valid dirfd value
  context.process_map[bpf_event_header.process_id].fd_map.insert(
      {1000, {"/usr/local/bin", true}});

  succeeded = SystemStateTracker::executeBinary(context,
                                                L_processContextFactory,
                                                bpf_event_header,
                                                bpf_event_header.process_id,
                                                1000,
                                                0,
                                                "test_binary",
                                                kExecArgumentList);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(factory_call_count, 0U);

  // Verify that:
  // 1. all the file descriptors marked as close-on-exec have been removed
  // 2. the binary path and argv in the process context entry have been updated
  EXPECT_EQ(context.process_map.size(), 1U);
  EXPECT_EQ(context.process_map.count(1001), 1U);

  const auto& process_context = context.process_map.at(1001);

  // The path we are expecting is: (process_context.fd_map.at(1000).path) +
  // "/test_binary"
  EXPECT_EQ(process_context.binary_path, "/usr/local/bin/test_binary");
  EXPECT_EQ(process_context.argv, kExecArgumentList);
  EXPECT_EQ(process_context.fd_map.size(), 1U);

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
  std::size_t factory_call_count{0U};

  auto L_processContextFactory = [&factory_call_count](ProcessContext&,
                                                       pid_t) -> bool {
    ++factory_call_count;
    return false;
  };

  SystemStateTracker::Context context;
  context.process_map.insert(
      {kBaseBPFEventHeader.process_id, kBaseProcessContext});

  std::string test_cwd_folder{"/home/alessandro"};
  auto succeeded =
      SystemStateTracker::setWorkingDirectory(context,
                                              L_processContextFactory,
                                              kBaseBPFEventHeader.process_id,
                                              test_cwd_folder);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(factory_call_count, 0U);
  ASSERT_EQ(context.process_map.count(kBaseBPFEventHeader.process_id), 1U);

  const auto& process_context =
      context.process_map.at(kBaseBPFEventHeader.process_id);
  EXPECT_EQ(process_context.cwd, test_cwd_folder);
  EXPECT_TRUE(context.event_list.empty());
}

TEST_F(SystemStateTrackerTests, set_working_directory_with_fd) {
  std::size_t factory_call_count{0U};

  auto L_processContextFactory = [&factory_call_count](ProcessContext&,
                                                       pid_t) -> bool {
    ++factory_call_count;
    return false;
  };

  SystemStateTracker::Context context;
  context.process_map.insert(
      {kBaseBPFEventHeader.process_id, kBaseProcessContext});

  std::string test_cwd_folder{"/home/alessandro"};
  context.process_map[kBaseBPFEventHeader.process_id].fd_map.insert(
      {2000, {test_cwd_folder, true}});

  auto succeeded = SystemStateTracker::setWorkingDirectory(
      context, L_processContextFactory, kBaseBPFEventHeader.process_id, 2000);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(factory_call_count, 0U);
  ASSERT_EQ(context.process_map.count(kBaseBPFEventHeader.process_id), 1U);

  const auto& process_context =
      context.process_map.at(kBaseBPFEventHeader.process_id);

  EXPECT_EQ(process_context.cwd, test_cwd_folder);
  EXPECT_TRUE(context.event_list.empty());
}

TEST_F(SystemStateTrackerTests, close_handle) {
  std::size_t factory_call_count{0U};

  auto L_processContextFactory = [&factory_call_count](ProcessContext&,
                                                       pid_t) -> bool {
    ++factory_call_count;
    return false;
  };

  SystemStateTracker::Context context;
  context.process_map.insert(
      {kBaseBPFEventHeader.process_id, kBaseProcessContext});

  std::string test_cwd_folder{"/home/alessandro"};
  context.process_map[kBaseBPFEventHeader.process_id].fd_map.insert(
      {2000, {test_cwd_folder, true}});

  EXPECT_EQ(context.process_map[kBaseBPFEventHeader.process_id].fd_map.size(),
            3U);

  auto succeeded = SystemStateTracker::closeHandle(
      context, L_processContextFactory, kBaseBPFEventHeader.process_id, 2000);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(factory_call_count, 0U);
  ASSERT_EQ(context.process_map.count(kBaseBPFEventHeader.process_id), 1U);

  const auto& process_context =
      context.process_map.at(kBaseBPFEventHeader.process_id);

  EXPECT_EQ(process_context.fd_map.size(), 2U);
  EXPECT_EQ(process_context.fd_map.count(2000), 0U);

  EXPECT_TRUE(context.event_list.empty());
}

TEST_F(SystemStateTrackerTests, duplicate_handle) {
  SystemStateTracker::Context context;
  auto succeeded =
      SystemStateTracker::duplicateHandle(context, 1212, 1, 2, true);

  EXPECT_FALSE(succeeded);
  EXPECT_TRUE(context.process_map.empty());

  context.process_map.insert(
      {kBaseBPFEventHeader.process_id, kBaseProcessContext});

  auto& process_context =
      context.process_map.at(kBaseBPFEventHeader.process_id);

  std::string test_file_path{"/home/alessandro/test.txt"};
  process_context.fd_map.insert({2000, {test_file_path, true}});
  EXPECT_EQ(process_context.fd_map.size(), 3U);

  succeeded = SystemStateTracker::duplicateHandle(
      context, kBaseBPFEventHeader.process_id, 1000, 3000, true);

  EXPECT_FALSE(succeeded);
  EXPECT_EQ(process_context.fd_map.size(), 3U);

  succeeded = SystemStateTracker::duplicateHandle(
      context, kBaseBPFEventHeader.process_id, 2000, 3000, true);

  EXPECT_TRUE(succeeded);
  ASSERT_EQ(context.process_map.count(kBaseBPFEventHeader.process_id), 1U);
  EXPECT_EQ(context.process_map.size(), 1U);
  EXPECT_EQ(process_context.fd_map.size(), 4U);

  ASSERT_EQ(process_context.fd_map.count(2000), 1U);
  const auto& fd_info1 = process_context.fd_map.at(2000);
  EXPECT_EQ(fd_info1.path, test_file_path);

  ASSERT_EQ(process_context.fd_map.count(3000), 1U);
  const auto& fd_info2 = process_context.fd_map.at(3000);
  EXPECT_EQ(fd_info2.path, test_file_path);

  EXPECT_TRUE(context.event_list.empty());
}

TEST_F(SystemStateTrackerTests, open_file) {
  std::size_t factory_call_count{0U};

  auto L_processContextFactory = [&factory_call_count](ProcessContext&,
                                                       pid_t) -> bool {
    ++factory_call_count;
    return false;
  };

  SystemStateTracker::Context context;
  context.process_map.insert(
      {kBaseBPFEventHeader.process_id, kBaseProcessContext});

  auto& process_context =
      context.process_map.at(kBaseBPFEventHeader.process_id);

  EXPECT_EQ(process_context.fd_map.size(), 2U);

  // Empty file path
  auto succeeded = SystemStateTracker::openFile(context,
                                                L_processContextFactory,
                                                kBaseBPFEventHeader.process_id,
                                                AT_FDCWD,
                                                10,
                                                "",
                                                0);

  EXPECT_FALSE(succeeded);
  EXPECT_EQ(process_context.fd_map.size(), 2U);
  EXPECT_EQ(factory_call_count, 0U);

  // Invalid dirfd
  succeeded = SystemStateTracker::openFile(context,
                                           L_processContextFactory,
                                           kBaseBPFEventHeader.process_id,
                                           11111, // Invalid dirfd value
                                           10,
                                           "test_file",
                                           0);

  EXPECT_FALSE(succeeded);
  EXPECT_EQ(process_context.fd_map.size(), 2U);
  EXPECT_EQ(factory_call_count, 0U);

  // Absolute paths, without close on exec
  std::string absolute_test_path{"/home/alessandro/Documents/secret.txt"};

  succeeded = SystemStateTracker::openFile(context,
                                           L_processContextFactory,
                                           kBaseBPFEventHeader.process_id,
                                           AT_FDCWD,
                                           10,
                                           absolute_test_path,
                                           0);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(process_context.fd_map.size(), 3U);
  ASSERT_EQ(process_context.fd_map.count(10), 1U);
  EXPECT_FALSE(process_context.fd_map.at(10).close_on_exec);
  EXPECT_EQ(process_context.fd_map.at(10).path, absolute_test_path);
  EXPECT_EQ(factory_call_count, 0U);

  // Absolute paths, with close on exec
  succeeded = SystemStateTracker::openFile(context,
                                           L_processContextFactory,
                                           kBaseBPFEventHeader.process_id,
                                           AT_FDCWD,
                                           11,
                                           absolute_test_path,
                                           O_CLOEXEC);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(process_context.fd_map.size(), 4U);
  ASSERT_EQ(process_context.fd_map.count(11), 1U);
  EXPECT_TRUE(process_context.fd_map.at(11).close_on_exec);
  EXPECT_EQ(process_context.fd_map.at(11).path, absolute_test_path);
  EXPECT_EQ(factory_call_count, 0U);

  // Relative paths + cwd, without close on exec
  std::string relative_test_path{"secret.txt"};

  succeeded = SystemStateTracker::openFile(context,
                                           L_processContextFactory,
                                           kBaseBPFEventHeader.process_id,
                                           AT_FDCWD,
                                           12,
                                           relative_test_path,
                                           0);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(process_context.fd_map.size(), 5U);
  ASSERT_EQ(process_context.fd_map.count(12), 1U);
  EXPECT_FALSE(process_context.fd_map.at(12).close_on_exec);
  EXPECT_EQ(process_context.fd_map.at(12).path,
            process_context.cwd + "/" + relative_test_path);
  EXPECT_EQ(factory_call_count, 0U);

  // Relative paths + cwd, with close on exec
  succeeded = SystemStateTracker::openFile(context,
                                           L_processContextFactory,
                                           kBaseBPFEventHeader.process_id,
                                           AT_FDCWD,
                                           13,
                                           relative_test_path,
                                           O_CLOEXEC);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(process_context.fd_map.size(), 6U);
  ASSERT_EQ(process_context.fd_map.count(13), 1U);
  EXPECT_TRUE(process_context.fd_map.at(13).close_on_exec);
  EXPECT_EQ(process_context.fd_map.at(13).path,
            process_context.cwd + "/" + relative_test_path);
  EXPECT_EQ(factory_call_count, 0U);

  // Relative paths + dirfd, without close on exec
  std::string dirfd_folder_path{"/etc"};
  std::string dirfd_relative_path{"hosts"};

  process_context.fd_map.insert({14, {dirfd_folder_path, true}});

  succeeded = SystemStateTracker::openFile(context,
                                           L_processContextFactory,
                                           kBaseBPFEventHeader.process_id,
                                           14, // FD to the /etc folder
                                           15,
                                           dirfd_relative_path,
                                           0);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(process_context.fd_map.size(), 8U);
  ASSERT_EQ(process_context.fd_map.count(15), 1U);
  EXPECT_FALSE(process_context.fd_map.at(15).close_on_exec);
  EXPECT_EQ(process_context.fd_map.at(15).path,
            dirfd_folder_path + "/" + dirfd_relative_path);
  EXPECT_EQ(factory_call_count, 0U);

  // Relative paths + dirfd, with close on exec
  succeeded = SystemStateTracker::openFile(context,
                                           L_processContextFactory,
                                           kBaseBPFEventHeader.process_id,
                                           14, // FD to the /etc folder
                                           16,
                                           dirfd_relative_path,
                                           O_CLOEXEC);

  EXPECT_TRUE(succeeded);
  EXPECT_EQ(process_context.fd_map.size(), 9U);
  ASSERT_EQ(process_context.fd_map.count(16), 1U);
  EXPECT_TRUE(process_context.fd_map.at(16).close_on_exec);
  EXPECT_EQ(process_context.fd_map.at(16).path,
            dirfd_folder_path + "/" + dirfd_relative_path);
  EXPECT_EQ(factory_call_count, 0U);
}
} // namespace osquery
