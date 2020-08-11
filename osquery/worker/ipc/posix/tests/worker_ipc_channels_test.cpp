/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <unistd.h>

#include <sys/resource.h>
#include <sys/time.h>

#include <gtest/gtest.h>

#ifdef OSQUERY_LINUX
#include <osquery/filesystem/linux/proc.h>
#endif
#include <osquery/worker/ipc/posix/pipe_channel.h>
#include <osquery/worker/ipc/posix/pipe_channel_factory.h>

#ifdef DARWIN
#include <boost/filesystem.hpp>
#endif

namespace osquery {
class WorkerIPCChannelsTest : public testing::Test {
 public:
  int getFdsOpen() {
#ifdef OSQUERY_LINUX
    std::map<std::string, std::string> open_descriptors;
    auto status = procDescriptors(std::to_string(getpid()), open_descriptors);

    if (!status.ok()) {
      return -1;
    }

    // The function always returns also the fd used find the open fds
    return open_descriptors.size() - 1;
#elif DARWIN
    std::string descriptors_path = "/dev/fd";
    boost::filesystem::directory_iterator it(descriptors_path), end;
    return std::distance(it, end) - 1;
#endif
  }

  // How many more fds we want to let the program open
  void setRelativeFDLimit(int fd_num) {
    auto current_fds_amount = getFdsOpen();

    struct rlimit file_limits {
      static_cast<rlim_t>(current_fds_amount + fd_num + 1),
          static_cast<rlim_t>(current_fds_amount + fd_num + 1)
    };
    auto result = setrlimit(RLIMIT_NOFILE, &file_limits);

    ASSERT_TRUE(result == 0)
        << "Failed to set the limit of file descriptors: " << strerror(errno);
  }
};

TEST_F(WorkerIPCChannelsTest, test_pipe_read_after_exit) {
  PipeChannelFactory factory;
  auto pipe_ticket = factory.createChannelTicket();

  int pid = fork();

  ASSERT_NE(pid, -1);

  if (pid == 0) {
    // Child
    auto& child_channel =
        factory.createChildChannel("test", std::move(pipe_ticket));

    child_channel.sendStringMessage("Hello World!");
    std::exit(testing::Test::HasFailure());
  } else {
    // Parent
    auto& parent_channel =
        factory.createParentChannel("test", std::move(pipe_ticket), pid);

    int wexit;
    waitpid(pid, &wexit, 0);
    ASSERT_EQ(WEXITSTATUS(wexit), 0);

    // We are able to read a message even after the child exited
    std::string message;
    auto status = parent_channel.recvStringMessage(message);

    ASSERT_TRUE(status.ok());

    EXPECT_EQ(message, "Hello World!");
  }
}

TEST_F(WorkerIPCChannelsTest, test_pipe_sigpipe) {
  PipeChannelFactory factory;
  auto pipe_ticket = factory.createChannelTicket();

  int pid = fork();

  ASSERT_NE(pid, -1);

  if (pid == 0) {
    // Child
    std::exit(testing::Test::HasFailure());
  } else {
    // Parent
    auto& parent_channel =
        factory.createParentChannel("test", std::move(pipe_ticket), pid);

    int wexit;
    waitpid(pid, &wexit, 0);
    ASSERT_EQ(WEXITSTATUS(wexit), 0);

    auto status = parent_channel.sendStringMessage("Hello World!");

    ASSERT_FALSE(status.ok());
    EXPECT_EQ(status.getCode(), EPIPE);
  }
}

TEST_F(WorkerIPCChannelsTest, test_pipe_close_while_reading) {
  PipeChannelFactory factory;
  auto pipe_ticket = factory.createChannelTicket();

  int pid = fork();

  ASSERT_NE(pid, -1);

  if (pid == 0) {
    // Child
    std::exit(testing::Test::HasFailure());
  } else {
    // Parent
    auto& parent_channel =
        factory.createParentChannel("test", std::move(pipe_ticket), pid);

    int wexit;
    waitpid(pid, &wexit, 0);
    ASSERT_EQ(WEXITSTATUS(wexit), 0);

    std::string message;
    auto status = parent_channel.recvStringMessage(message);

    ASSERT_FALSE(status.ok());
  }
}

TEST_F(WorkerIPCChannelsTest, test_pipe_ticket_leak) {
  // Give enough fds for one pipe
  setRelativeFDLimit(2);

  int fds_open = getFdsOpen();
  PipeChannelFactory factory;
  ASSERT_THROW(factory.createChannelTicket(), std::runtime_error);

  // Check we aren't leaking any fd
  ASSERT_EQ(getFdsOpen(), fds_open);

  setRelativeFDLimit(4);

  fds_open = getFdsOpen();
  auto ticket = factory.createChannelTicket();

  // Check that there are actually two new fds for the pipes
  ASSERT_EQ(getFdsOpen(), fds_open + 4);
}
} // namespace osquery
