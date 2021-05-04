/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "../logrotate.h"

#include <osquery/core/flags.h>

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

namespace osquery {

DECLARE_uint64(logger_rotate_size);
DECLARE_uint64(logger_rotate_max_files);

class LogRotateTests : public testing::Test {
 public:
  void SetUp() override {}
  void TearDown() override {}
};

class FakeLogRotate : public LogRotate {
 public:
  FakeLogRotate(const std::string& path) : LogRotate(path) {}

  void insertFile(const std::string& filepath, size_t filesize) {
    fs_[filepath] = filesize;
  }

  void setRotateSize(size_t size) {
    rotate_size_ = size;
  }

 private:
  size_t fileSize(const std::string& filepath) override {
    auto it = fs_.find(filepath);
    if (it == fs_.end()) {
      return 0;
    }
    return it->second;
  }

  size_t getRotateSize() override {
    return rotate_size_;
  }

  bool pathExists(const std::string& path) override {
    return fs_.find(path) != fs_.end();
  }

  Status removeFile(const std::string& path) override {
    auto it = fs_.find(path);
    if (it == fs_.end()) {
      return Status::failure("File does not exist");
    }

    fs_.erase(it);
    return Status::success();
  }

  Status moveFile(const std::string& source, const std::string& dest) override {
    auto it = fs_.find(source);
    if (it == fs_.end()) {
      return Status::failure("File does not exist");
    }

    fs_[dest] = it->second;
    fs_.erase(it);
    return Status::success();
  }

  Status compressFile(const std::string& source,
                      const std::string& dest) override {
    auto s = this->moveFile(source, dest);
    if (!s.ok()) {
      return s;
    }

    fs_[dest] = fs_[dest] / 2;
    return Status::success();
  }

 private:
  /// Pathname -> size.
  std::map<std::string, size_t> fs_;
  size_t rotate_size_{0};

 private:
  FRIEND_TEST(LogRotateTests, test_should_rotate);
  FRIEND_TEST(LogRotateTests, test_rotate);
  FRIEND_TEST(LogRotateTests, test_rotate_missing_file);
  FRIEND_TEST(LogRotateTests, test_rotate_overflow);
};

TEST_F(LogRotateTests, test_should_rotate) {
  FakeLogRotate rotate("/doesnotexist/logdir");
  rotate.insertFile("/doesnotexist/logdir", 100);
  rotate.setRotateSize(101);

  EXPECT_FALSE(rotate.shouldRotate());
  rotate.setRotateSize(100);
  EXPECT_TRUE(rotate.shouldRotate());
}

TEST_F(LogRotateTests, test_rotate) {
  FakeLogRotate rotate("/doesnotexist/logdir");
  rotate.insertFile("/doesnotexist/logdir", 100);
  rotate.setRotateSize(100);
  rotate.rotate(5);

  ASSERT_TRUE(rotate.pathExists("/doesnotexist/logdir.1"));
  EXPECT_EQ(rotate.fileSize("/doesnotexist/logdir.1"), 100);
  EXPECT_FALSE(rotate.pathExists("/doesnotexist/logdir"));
}

TEST_F(LogRotateTests, test_rotate_missing_file) {
  FakeLogRotate rotate("/doesnotexist/logdir");
  rotate.insertFile("/doesnotexist/logdir", 1000);
  rotate.insertFile("/doesnotexist/logdir.1", 8000);
  rotate.setRotateSize(100);
  rotate.rotate(5);

  ASSERT_TRUE(rotate.pathExists("/doesnotexist/logdir.2.zst"));
  // Expect this to be compressed.
  EXPECT_EQ(rotate.fileSize("/doesnotexist/logdir.2.zst"), 4000);
  EXPECT_TRUE(rotate.pathExists("/doesnotexist/logdir.1"));
  EXPECT_EQ(rotate.fileSize("/doesnotexist/logdir.1"), 1000);

  // Try another rotate.
  rotate.insertFile("/doesnotexist/logdir", 500);
  rotate.rotate(5);
  ASSERT_TRUE(rotate.pathExists("/doesnotexist/logdir.3.zst"));
  EXPECT_EQ(rotate.fileSize("/doesnotexist/logdir.3.zst"), 4000);
  EXPECT_EQ(rotate.fileSize("/doesnotexist/logdir.2.zst"), 500);
  EXPECT_EQ(rotate.fileSize("/doesnotexist/logdir.1"), 500);

  auto s = rotate.rotate(5);
  ASSERT_FALSE(s.ok());
  EXPECT_EQ(rotate.fileSize("/doesnotexist/logdir.1"), 500);
}

TEST_F(LogRotateTests, test_rotate_overflow) {
  FakeLogRotate rotate("/doesnotexist/logdir");
  rotate.insertFile("/doesnotexist/logdir", 100);
  rotate.insertFile("/doesnotexist/logdir.1", 500);
  rotate.insertFile("/doesnotexist/logdir.2.zst", 800);
  rotate.insertFile("/doesnotexist/logdir.3.zst", 2000);
  rotate.setRotateSize(100);
  rotate.rotate(3);

  EXPECT_FALSE(rotate.pathExists("/doesnotexist/logdir"));
  EXPECT_FALSE(rotate.pathExists("/doesnotexist/logdir.4.zst"));
  EXPECT_EQ(rotate.fileSize("/doesnotexist/logdir.1"), 100);
  EXPECT_EQ(rotate.fileSize("/doesnotexist/logdir.2.zst"), 250);
  EXPECT_EQ(rotate.fileSize("/doesnotexist/logdir.3.zst"), 800);

  // Rotate owns these files so a 'new' max rotate will remove old files.
  rotate.insertFile("/doesnotexist/logdir", 3000);
  rotate.rotate(2);

  EXPECT_FALSE(rotate.pathExists("/doesnotexist/logdir"));
  EXPECT_FALSE(rotate.pathExists("/doesnotexist/logdir.3.zst"));
  EXPECT_EQ(rotate.fileSize("/doesnotexist/logdir.1"), 3000);
  EXPECT_EQ(rotate.fileSize("/doesnotexist/logdir.2.zst"), 50);
}

} // namespace osquery
