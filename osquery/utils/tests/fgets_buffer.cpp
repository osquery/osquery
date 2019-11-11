/**
 *  Copyright (c) 2019-present, osquery Foundation
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <gtest/gtest.h>

#include <osquery/utils/fgets_buffer.h>

static const std::string TEST1 = "one\ntwo\nthree\n";
static const std::string TEST2 = "abcdef0123456789";

namespace osquery {

class fgetsTest : public ::testing::Test {
 protected:
  virtual void SetUp() {}
};

struct FakeFile : public NonblockingFile {
  virtual ~FakeFile() {}
  bool isValid() override {
    return isValid_;
  }

  bool isDataAvail() override {
    return !buf_.empty();
  };

  int64_t read(std::vector<char>& dest) override {
    size_t remaining = dest.capacity() - dest.size();
    size_t len = (buf_.size() > remaining ? remaining : buf_.size());
    auto p = dest.data() + dest.size();
    dest.resize(dest.size() + len);
    memcpy(p, buf_.data(), len);
    buf_.clear();
    return (int64_t)len;
  }

  void close() override {}

  bool isValid_{true};
  std::string buf_;
};

TEST_F(fgetsTest, basic) {
  auto spFile = std::make_unique<FakeFile>();
  spFile->buf_ = TEST1;
  FgetsBuffer fb(std::move(spFile), 16 /* max line length */);
  std::string line;

  // "one\ntwo\nthree\n"

  auto status = fb.fgets(line);
  ASSERT_FALSE(status);
  ASSERT_EQ("one", line);

  status = fb.fgets(line);
  ASSERT_FALSE(status);
  ASSERT_EQ("two", line);

  status = fb.fgets(line);
  ASSERT_FALSE(status);
  ASSERT_EQ("three", line);
}

TEST_F(fgetsTest, basic_with_newline) {
  auto spFile = std::make_unique<FakeFile>();
  spFile->buf_ = TEST1;
  FgetsBuffer fb(
      std::move(spFile), 16 /* max line length */, true /* include newline */);
  std::string line;

  // "one\ntwo\nthree\n"

  auto status = fb.fgets(line);
  ASSERT_FALSE(status);
  ASSERT_EQ("one\n", line);

  status = fb.fgets(line);
  ASSERT_FALSE(status);
  ASSERT_EQ("two\n", line);

  status = fb.fgets(line);
  ASSERT_FALSE(status);
  ASSERT_EQ("three\n", line);
}

TEST_F(fgetsTest, test_max) {
  auto spFile = std::make_unique<FakeFile>();
  spFile->buf_ = TEST2 + "\n";
  FgetsBuffer fb(std::move(spFile), TEST2.size() /* max line length */);
  std::string line;
  auto status = fb.fgets(line);
  ASSERT_TRUE(status);
  ASSERT_EQ(TEST2.size(), fb.getNumDroppedChars());
}

TEST_F(fgetsTest, multi_read) {
  std::string line;
  auto spFile = std::make_unique<FakeFile>();
  spFile->buf_ = "Once ";

  // for test purposes, violate unique with direct access
  auto pFile = spFile.get();

  FgetsBuffer fb(std::move(spFile), 64 /* max line length */);

  auto status = fb.fgets(line);
  ASSERT_TRUE(status);

  pFile->buf_ = "upon ";
  status = fb.fgets(line);
  ASSERT_TRUE(status);

  // nothing to read
  status = fb.fgets(line);
  ASSERT_TRUE(status);

  pFile->buf_ = "a time ";
  status = fb.fgets(line);
  ASSERT_TRUE(status);

  pFile->buf_ = "it ended.\n";
  status = fb.fgets(line);
  ASSERT_FALSE(status);
  ASSERT_EQ("Once upon a time it ended.", line);
}
} // namespace osquery
