/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cstdlib>
#include <string>

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>

#include <osquery/utils/pidfile/pidfile.h>

#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

#else
#include <unistd.h>
#endif

namespace osquery {

namespace {

class UniquePath final {
 public:
  static UniquePath create() {
    auto path = boost::filesystem::temp_directory_path() /
                boost::filesystem::unique_path();
    return UniquePath(path.string());
  }

  ~UniquePath() {
    boost::filesystem::remove(path);
  }

  const std::string& get() const {
    return path;
  }

  UniquePath(const UniquePath&) = delete;
  UniquePath& operator=(const UniquePath&) = delete;

 private:
  UniquePath(const std::string& str) : path(str) {}

  std::string path;
};

std::string getErrorMessage(Pidfile::Error error_code) {
  std::stringstream buffer;
  buffer << error_code;

  return buffer.str();
}

template <typename Value>
std::string getErrorMessage(const Expected<Value, Pidfile::Error>& expected) {
  return getErrorMessage(expected.getErrorCode());
}

} // namespace

class PidfileTests : public testing::Test {};

TEST_F(PidfileTests, test_pidfile) {
  // Create an initial pidfile, this should always succeed
  auto path1 = UniquePath::create();

  auto res1 = Pidfile::create(path1.get());
  ASSERT_FALSE(res1.isError()) << getErrorMessage(res1);

  // Attempt to create a secondary pidfile on the same path. This
  // should always fail. Try this multiple times to make sure we
  // are not changing the lock state
  for (int i = 0; i < 5; ++i) {
    auto res2 = Pidfile::create(path1.get());
    ASSERT_TRUE(res2.isError());
    ASSERT_EQ(res2.getErrorCode(), Pidfile::Error::Busy);
  }

  // Create a new pidfile on a different path, this must succeed
  auto path2 = UniquePath::create();

  auto res3 = Pidfile::create(path2.get());
  ASSERT_FALSE(res3.isError()) << getErrorMessage(res3);

  // Destroy the initial pidfile
  res1.take();

  // Attempt once more to create the pidfile with the initial
  // path. This must succeed since we destroyed the old file
  auto res4 = Pidfile::create(path1.get());
  ASSERT_FALSE(res4.isError()) << getErrorMessage(res4);

  // Destroy the second pidfile
  res4.take();

  // One last time, overwriting an old Pidfile
  auto path3 = UniquePath::create();

  {
    std::fstream test_file(path3.get().c_str(), std::ios::out);
    ASSERT_FALSE(!test_file) << "Failed to create the broken pidfile";

    test_file << "test_test";
    ASSERT_FALSE(!test_file) << "Failed to initialize the broken pidfile";
  }

  ASSERT_TRUE(boost::filesystem::exists(path3.get()))
      << "The fake pidfile was not initialized correctly";

  auto res5 = Pidfile::create(path3.get());
  ASSERT_FALSE(res5.isError()) << getErrorMessage(res5);

  // Also check the contents
#ifdef WIN32
  auto expected_pid = static_cast<int>(GetCurrentProcessId());
#else
  auto expected_pid = static_cast<int>(getpid());
#endif

  auto pidfile_data_exp = Pidfile::read(path3.get());
  ASSERT_FALSE(pidfile_data_exp.isError()) << getErrorMessage(pidfile_data_exp);

  auto pidfile_data = pidfile_data_exp.take();

  EXPECT_EQ(pidfile_data, expected_pid)
      << "The fake pidfile was not correctly overwritten with the current PID";

  // Release the pidfile, then try again to read the pid. This will fail
  // because the lock operation will succeed, indicating there is no
  // osquery process keeping the file busy
  res5.take();

  pidfile_data_exp = Pidfile::read(path3.get());
  ASSERT_TRUE(pidfile_data_exp.isError());
  EXPECT_EQ(pidfile_data_exp.getErrorCode(), Pidfile::Error::NotRunning);
}

} // namespace osquery
