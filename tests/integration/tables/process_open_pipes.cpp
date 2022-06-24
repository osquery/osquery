/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for process_open_pipes
// Spec file: specs/linux/process_open_pipes.table

#include <osquery/logger/logger.h>
#include <osquery/tests/integration/tables/helper.h>

#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

namespace osquery {
namespace table_tests {

class ProcessOpenPipesTest : public testing::Test {
 private:
  std::string pipe_path_;
  std::string dir_path_;
  std::string test_type_;
  int fd_[2] = {-1};
  int fd_signal_[2] = {-1};

  void SetUp() override {
    setUpEnvironment();
    dir_path_ = std::string();
    char dir_template[] = "/tmp/tmpdir.XXXXXX";
    if (!mkdtemp(dir_template)) {
      return;
    }
    dir_path_ = std::string(dir_template);
    pipe_path_ = dir_path_ + "/test_pipe";
    if (mkfifo(pipe_path_.c_str(), 0600)) {
      dir_path_ = std::string();
    }
    if (pipe(fd_signal_) == -1) {
      LOG(ERROR) << "Error creating signal pipe\n";
    }
  }

  void TearDown() override {
    remove(pipe_path_.c_str());
    rmdir(dir_path_.c_str());
    close(fd_[0]);
    close(fd_[1]);
    close(fd_signal_[0]);
    close(fd_signal_[1]);
  }

  void runForever() {
    while (true) {
    }
  }

  void signal_parent() {
    char buf = '1';
    write(fd_signal_[1], &buf, 1);
  }

  int setup_writer() {
    close(fd_signal_[0]);
    if (test_type_ == "named_pipe") {
      int fd = open(pipe_path_.c_str(), O_WRONLY);
      if (fd == -1) {
        LOG(ERROR) << "Error in opening named pipe";
      }
      return fd;
    } else { // unnamed_pipe
      close(fd_[0]);
      return fd_[1];
    }
  }

  int setup_reader() {
    close(fd_signal_[0]);
    if (test_type_ == "named_pipe") {
      int fd = open(pipe_path_.c_str(), O_RDONLY);
      if (fd == -1) {
        LOG(ERROR) << "Error in opening named pipe";
      }
      return fd;
    } else { // unnamed_pipe
      close(fd_[1]);
      return fd_[0];
    }
  }

  void do_writer() {
    std::string buf = "test";

    int fd = setup_writer();
    if (fd == -1) {
      signal_parent();
      return;
    }

    if (write(fd, buf.c_str(), buf.length()) == -1) {
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
    read(fd_signal_[0], &buf, 1);
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
    test_result_ = data.size();
  }

  void kill_children(int writer_pid, int reader_pid) {
    kill(writer_pid, SIGKILL);
    kill(reader_pid, SIGKILL);
    waitpid(writer_pid, nullptr, 0);
    waitpid(reader_pid, nullptr, 0);
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
  int test_result_;

  void test_named_pipe() {
    test_type_ = "named_pipe";
    test_result_ = 0;

    if (dir_path_.empty()) {
      LOG(ERROR) << "Error creating tmp dir for test";
      return;
    }

    do_children();
  }

  void test_unnamed_pipe() {
    test_type_ = "unnamed_pipe";
    test_result_ = 0;

    if (pipe(fd_) == -1) {
      LOG(ERROR) << "Error creating unnamed pipe";
      return;
    }

    do_children();
  }
};

TEST_F(ProcessOpenPipesTest, test_sanity) {
  test_named_pipe();
  ASSERT_GT(test_result_, 0);
  test_unnamed_pipe();
  ASSERT_GT(test_result_, 0);
}

} // namespace table_tests
} // namespace osquery
