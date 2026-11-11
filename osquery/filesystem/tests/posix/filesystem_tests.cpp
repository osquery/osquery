/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/filesystem.hpp>

#include <gtest/gtest.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <osquery/filesystem/fileops.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/tests/test_util.h>

namespace fs = boost::filesystem;

namespace osquery {

class PosixFilesystemTests : public testing::Test {
 protected:
  fs::path test_working_dir_;

  void SetUp() override {
    test_working_dir_ = fs::temp_directory_path() /
                        fs::unique_path("osquery.test_working_dir.%%%%.%%%%");
    fs::create_directories(test_working_dir_);
  }

  void TearDown() override {
    fs::remove_all(test_working_dir_);
  }
};

TEST_F(PosixFilesystemTests, test_read_unopened_fifo) {
  // A FIFO is not a regular file: readFile refuses it, without hanging.
  auto test_file = test_working_dir_ / "fifo";
  ASSERT_EQ(::mkfifo(test_file.c_str(), S_IRUSR | S_IWUSR), 0);

  std::string content;
  EXPECT_FALSE(readFile(test_file, content));
  EXPECT_TRUE(content.empty());
  ::unlink(test_file.c_str());
}

TEST_F(PosixFilesystemTests, test_read_fifo_leaves_its_data) {
  // Reading a FIFO would take the data another process wrote for its reader.
  auto fifo = test_working_dir_ / "fifo";
  ASSERT_EQ(::mkfifo(fifo.c_str(), S_IRUSR | S_IWUSR), 0);

  int reader = ::open(fifo.c_str(), O_RDONLY | O_NONBLOCK);
  ASSERT_GE(reader, 0);
  int writer = ::open(fifo.c_str(), O_WRONLY | O_NONBLOCK);
  ASSERT_GE(writer, 0);
  ASSERT_EQ(::write(writer, "data", 4), 4);

  std::string content;
  EXPECT_FALSE(readFile(fifo, content));
  EXPECT_TRUE(content.empty());

  char buffer[4];
  EXPECT_EQ(::read(reader, buffer, sizeof(buffer)), 4);

  ::close(writer);
  ::close(reader);
}

TEST_F(PosixFilesystemTests, test_read_symlink_to_device) {
  // A device reached through a symlink is refused without being opened.
  auto link = test_working_dir_ / "link";
  fs::create_symlink("/dev/null", link);

  std::string content;
  EXPECT_FALSE(readFile(link, content));
}

TEST_F(PosixFilesystemTests, test_read_symlink_to_regular_file) {
  auto target = test_working_dir_ / "target";
  ASSERT_TRUE(writeTextFile(target, "content"));
  auto link = test_working_dir_ / "link";
  fs::create_symlink(target, link);

  std::string content;
  ASSERT_TRUE(readFile(link, content));
  EXPECT_EQ(content, "content");
}

TEST_F(PosixFilesystemTests, test_regular_only_opens_regular_file) {
  auto path = test_working_dir_ / "file";
  ASSERT_TRUE(writeTextFile(path, "content"));

  PlatformFile file(path, PF_OPEN_EXISTING | PF_READ | PF_REGULAR_ONLY);
  ASSERT_TRUE(file.isValid());
  EXPECT_NE(::fcntl(file.nativeHandle(), F_GETFD) & FD_CLOEXEC, 0);

  char buffer[7];
  EXPECT_EQ(file.read(buffer, sizeof(buffer)), 7);
  EXPECT_EQ(std::string(buffer, sizeof(buffer)), "content");
}

TEST_F(PosixFilesystemTests, test_regular_only_follows_directory_symlink) {
  auto dir = test_working_dir_ / "dir";
  ASSERT_TRUE(fs::create_directory(dir));
  ASSERT_TRUE(writeTextFile(dir / "file", "content"));
  auto dir_link = test_working_dir_ / "dir_link";
  fs::create_symlink(dir, dir_link);

  PlatformFile file(dir_link / "file",
                    PF_OPEN_EXISTING | PF_READ | PF_REGULAR_ONLY);
  ASSERT_TRUE(file.isValid());

  char buffer[7];
  EXPECT_EQ(file.read(buffer, sizeof(buffer)), 7);
  EXPECT_EQ(std::string(buffer, sizeof(buffer)), "content");
}

TEST_F(PosixFilesystemTests, test_regular_only_opens_relative_path) {
  ASSERT_TRUE(writeTextFile(test_working_dir_ / "file", "content"));

  auto cwd = fs::current_path();
  fs::current_path(test_working_dir_);
  PlatformFile file("file", PF_OPEN_EXISTING | PF_READ | PF_REGULAR_ONLY);
  bool valid = file.isValid();
  fs::current_path(cwd);
  EXPECT_TRUE(valid);
}

TEST_F(PosixFilesystemTests, test_regular_only_refuses_fifo) {
  // Without a writer, a blocking open of the FIFO would never return.
  auto fifo = test_working_dir_ / "fifo";
  ASSERT_EQ(::mkfifo(fifo.c_str(), S_IRUSR | S_IWUSR), 0);

  bool valid = true;
  EXPECT_TRUE(returnsWithoutBlockingOnFifo(fifo, [&fifo, &valid]() {
    PlatformFile file(fifo, PF_OPEN_EXISTING | PF_READ | PF_REGULAR_ONLY);
    valid = file.isValid();
  }));
  EXPECT_FALSE(valid);
}

TEST_F(PosixFilesystemTests, test_regular_only_refuses_device_and_directory) {
  auto link = test_working_dir_ / "link";
  fs::create_symlink("/dev/null", link);
  auto dir_link = test_working_dir_ / "dir_link";
  fs::create_symlink("/dev", dir_link);

  for (const auto& path :
       {fs::path("/dev/null"), link, dir_link / "null", test_working_dir_}) {
    PlatformFile file(path, PF_OPEN_EXISTING | PF_READ | PF_REGULAR_ONLY);
    EXPECT_FALSE(file.isValid()) << path;
  }
}
} // namespace osquery
