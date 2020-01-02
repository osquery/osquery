/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

// Sanity check integration test for process_open_pipes
// Spec file: specs/posix/process_open_pipes.table

#include <osquery/logger.h>
#include <osquery/tests/integration/tables/helper.h>

#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

namespace osquery {
namespace table_tests {

class ProcessOpenPipesTest : public testing::Test {
  std::string pipe_path;
  std::string dir_path;
  std::string test_type;
  int fd[2];
  int fd_signal[2];

  void SetUp() override {
    setUpEnvironment();
    dir_path = std::string();
    char dir_template[] = "/tmp/tmpdir.XXXXXX";
    if (!mkdtemp(dir_template)) {
      return;
    }
    dir_path = std::string(dir_template);
    pipe_path = dir_path + "/test_pipe";
    if (mkfifo(pipe_path.c_str(), 0600)) {
      dir_path = std::string();
    }
    if (pipe(fd_signal) == -1) {
      LOG(ERROR) << "Error creating signal pipe\n";
    }
  }

  void TearDown() override {
    remove(pipe_path.c_str());
    rmdir(dir_path.c_str());
    close(fd[0]);
    close(fd[1]);
    close(fd_signal[0]);
    close(fd_signal[1]);
  }

  void runForever() {
    while (true) {
    }
  }
  void signal_parent() {
    char buf = '1';
    write(fd_signal[1], &buf, 1);
  }

  int setup_writer() {
    close(fd_signal[0]);
    if (test_type == "named_pipe") {
      int fd = open(pipe_path.c_str(), O_WRONLY);
      if (fd == -1) {
        LOG(ERROR) << "Error in opening named pipe";
      }
      return fd;
    } else { // unnamed_pipe
      close(fd[0]);
      return fd[1];
    }
  }

  int setup_reader() {
    close(fd_signal[0]);
    if (test_type == "named_pipe") {
      int fd = open(pipe_path.c_str(), O_RDONLY);
      if (fd == -1) {
        LOG(ERROR) << "Error in opening named pipe";
      }
      return fd;
    } else { // unnamed_pipe
      close(fd[1]);
      return fd[0];
    }
  }

  void do_writer() {
    char buf[] = "test";

    int fd = setup_writer();
    if (fd == -1) {
      signal_parent();
      return;
    }

    if (write(fd, "test", sizeof(buf)) == -1) {
      signal_parent();
      return;
    }

    runForever();
  }

  void do_reader() {
    std::array<char, 10> buf;

    int fd = setup_reader();
    if (fd == -1) {
      signal_parent();
      return;
    }

    if (read(fd, buf.data(), 10) == -1) {
      signal_parent();
      return;
    }

    signal_parent();
    runForever();
  }

  int create_child(std::string child_type) {
    int ret = fork();
    switch (ret) {
    case -1:
      LOG(ERROR) << "Error in fork()";
      break;
    case 0: // child
      if (child_type == "reader") {
        do_reader();
      } else {
        do_writer();
      }
      break;
    default: // parent
      break;
    }
    return ret;
  }

  void wait_child_signal() {
    char buf;
    read(fd_signal[0], &buf, 1);
  }

  void do_query(int writer_pid, int reader_pid) {
    QueryData data =
        execute_query("select * from process_open_pipes where pid = " +
                      std::to_string(writer_pid) +
                      " and partner_pid = " + std::to_string(reader_pid));
    ASSERT_GT(data.size(), 0ul);
    ValidationMap row_map = {
        {"pid", NonNegativeInt},
        {"fd", NonNegativeInt},
        {"mode", NonEmptyString},
        {"inode", NonNegativeInt},
        {"type", NonEmptyString},
        {"partner_pid", NonNegativeInt},
        {"partner_fd", NonNegativeInt},
        {"partner_mode", NonEmptyString},
    };
    validate_rows(data, row_map);
    test_result = data.size();
  }

  void kill_children(int writer_pid, int reader_pid) {
    kill(writer_pid, SIGKILL);
    kill(reader_pid, SIGKILL);
    waitpid(writer_pid, NULL, 0);
    waitpid(reader_pid, NULL, 0);
  }

  void do_children() {
    int writer_pid = create_child("writer");
    if (writer_pid <= 0) {
      LOG(ERROR) << "Error creating writer child";
      return;
    }

    int reader_pid = create_child("reader");
    if (reader_pid <= 0) {
      LOG(ERROR) << "Error creating writer child";
      return;
    }

    wait_child_signal();
    do_query(writer_pid, reader_pid);
    kill_children(writer_pid, reader_pid);
  }

 public:
  int test_result;

  void test_named_pipe() {
    test_type = "named_pipe";
    test_result = 0;

    if (dir_path.empty()) {
      LOG(ERROR) << "Error creating tmp dir for test";
      return;
    }

    do_children();
  }

  void test_unnamed_pipe() {
    test_type = "unnamed_pipe";
    test_result = 0;

    if (pipe(fd) == -1) {
      LOG(ERROR) << "Error creating unnamed pipe";
      return;
    }

    do_children();
  }
};

TEST_F(ProcessOpenPipesTest, test_sanity) {
  test_named_pipe();
  ASSERT_GT(test_result, 0);
  test_unnamed_pipe();
  ASSERT_GT(test_result, 0);
}

} // namespace table_tests
} // namespace osquery
