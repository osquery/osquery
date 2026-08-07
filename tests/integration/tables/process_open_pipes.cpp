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

#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <osquery/logger/logger.h>
#include <osquery/tests/integration/tables/helper.h>

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
      pause();
    }
  }

  void signal_parent(bool success) {
    char buf = success ? '1' : '0';
    write(fd_signal_[1], &buf, 1);
  }

  void do_writer() {
    if (test_type_ == "named_pipe") {
      int fd = open(pipe_path_.c_str(), O_WRONLY);
      if (fd == -1) {
        LOG(ERROR) << "Writer: Error opening named pipe";
        signal_parent(false);
        return;
      }
    } else { // unnamed_pipe, close read end
      close(fd_[0]);
    }

    signal_parent(true);
    runForever();
  }

  void do_reader() {
    if (test_type_ == "named_pipe") {
      int fd = open(pipe_path_.c_str(), O_RDONLY);
      if (fd == -1) {
        LOG(ERROR) << "Reader: Error opening named pipe";
        signal_parent(false);
        return;
      }
    } else { // unnamed_pipe, close write end
      close(fd_[1]);
    }

    signal_parent(true);
    runForever();
  }

  int create_child(std::string child_type) {
    int ret = fork();
    switch (ret) {
    case -1:
      LOG(ERROR) << "Error in fork()";
      break;
    case 0: // child
      close(fd_signal_[0]); // child only writes to signal pipe, close read end
      if (child_type == "reader") {
        do_reader();
      } else {
        do_writer();
      }
      _exit(1);
    default: // parent
      break;
    }
    return ret;
  }

  bool wait_child_signal() {
    char buf;
    if (read(fd_signal_[0], &buf, 1) != 1) {
      return false;
    }

    return buf == '1';
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
    if (writer_pid > 0) {
      kill(writer_pid, SIGKILL);
      waitpid(writer_pid, nullptr, 0);
    }

    if (reader_pid > 0) {
      kill(reader_pid, SIGKILL);
      waitpid(reader_pid, nullptr, 0);
    }
  }

  void do_children() {
    int reader_pid = create_child("reader");
    if (reader_pid <= 0) {
      LOG(ERROR) << "Error creating reader child";
      return;
    }

    int writer_pid = create_child("writer");
    if (writer_pid <= 0) {
      LOG(ERROR) << "Error creating writer child";
      kill_children(writer_pid, reader_pid);
      return;
    }

    // Parent only reads, close the write end.
    close(fd_signal_[1]);

    if (!(wait_child_signal() && wait_child_signal())) {
      FAIL() << "Child processes failed to initialize";
      kill_children(writer_pid, reader_pid);
      return;
    }

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

TEST_F(ProcessOpenPipesTest, test_named_pipe) {
  test_named_pipe();
  ASSERT_GT(test_result_, 0);
}

TEST_F(ProcessOpenPipesTest, test_unnamed_pipe) {
  test_unnamed_pipe();
  ASSERT_GT(test_result_, 0);
}

} // namespace table_tests
} // namespace osquery
