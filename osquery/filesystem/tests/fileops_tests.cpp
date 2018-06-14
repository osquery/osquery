/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>

#include <osquery/core.h>

#include "osquery/filesystem/fileops.h"
#include "osquery/tests/test_util.h"

namespace fs = boost::filesystem;

namespace osquery {

class FileOpsTests : public testing::Test {
 protected:
  void SetUp() override {
    createMockFileStructure();
  }

  void TearDown() override {
    tearDownMockFileStructure();
  }

  bool globResultsMatch(const std::vector<std::string>& results,
                        const std::vector<fs::path>& expected) {
    // Sets cannot be the same if they are different sizes
    if (results.size() != expected.size()) {
      return false;
    }
    // Convert the data structure to a set for better searching
    std::set<std::string> results_set;
    for (const auto& res : results) {
      results_set.insert(res);
    }

    for (auto res : expected) {
      const auto loc = results_set.find(res.make_preferred().string());
      // Unable to find element (something is in expected but not results)
      if (loc == results_set.end()) {
        return false;
      }
      // Pair found so remove from results
      results_set.erase(loc);
    }

    // There are unremoved values so expected is a proper subset of results
    if (!results_set.empty()) {
      return false;
    }
    return true;
  }
};

class TempFile {
 public:
  TempFile() {
    do {
      path_ = generateTempPath();
    } while (fs::exists(path_));
  }

  ~TempFile() {
    if (fs::exists(path_)) {
      fs::remove(path_);
    }
  }

  const std::string& path() const {
    return path_;
  }

 private:
  static std::string generateTempPath() {
    return (fs::temp_directory_path() / fs::unique_path("osquery-%%%%-%%%%"))
        .make_preferred()
        .string();
  }

 private:
  std::string path_;
};

TEST_F(FileOpsTests, test_openFile) {
  TempFile tmp_file;
  std::string path = tmp_file.path();

  {
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_READ);
    EXPECT_FALSE(fd.isValid());
  }

  {
    PlatformFile fd(path, PF_CREATE_NEW | PF_WRITE);
    EXPECT_TRUE(fd.isValid());
  }

  {
    PlatformFile fd(path, PF_CREATE_NEW | PF_READ);
    EXPECT_FALSE(fd.isValid());
  }

  fs::remove(path);

  {
    PlatformFile fd(path, PF_CREATE_ALWAYS | PF_READ);
    EXPECT_TRUE(fd.isValid());
  }

  {
    PlatformFile fd(path, PF_CREATE_ALWAYS | PF_READ);
    EXPECT_TRUE(fd.isValid());
  }

  {
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_READ);
    EXPECT_TRUE(fd.isValid());
  }
}

/*
 * This is a special function for testing file share operations on Windows. Our
 * PlatformFile as of now will only set FILE_SHARE_READ to play nicely with log
 * reading tools. However, we need to create one with FILE_SHARE_READ and
 * FILE_SHARE_WRITE for testing.
 */
std::unique_ptr<PlatformFile> openRWSharedFile(const std::string& path,
                                               int mode) {
#ifdef WIN32
  DWORD access_mask = -1;
  DWORD creation_disposition = -1;

  if (mode == (PF_OPEN_EXISTING | PF_READ)) {
    access_mask = PF_READ;
    creation_disposition = OPEN_EXISTING;
  } else if (mode == (PF_OPEN_ALWAYS | PF_WRITE)) {
    access_mask = PF_WRITE;
    creation_disposition = OPEN_ALWAYS;
  }

  HANDLE handle = ::CreateFileA(path.c_str(),
                                access_mask,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr,
                                creation_disposition,
                                0,
                                nullptr);
  return std::unique_ptr<PlatformFile>(new PlatformFile(handle));
#else
  return std::unique_ptr<PlatformFile>(new PlatformFile(path, mode));
#endif
}

/// Some permissions do not apply to POSIX root.
static bool isUserPOSIXAdmin() {
  return !isPlatform(PlatformType::TYPE_WINDOWS) && isUserAdmin();
}

TEST_F(FileOpsTests, test_shareRead) {
  TempFile tmp_file;
  std::string path = tmp_file.path();

  const char* test1_data = "AAAABBBB";
  const ssize_t test1_size = ::strlen(test1_data);

  {
    PlatformFile fd(path, PF_CREATE_NEW | PF_WRITE);
    ASSERT_TRUE(fd.isValid());
    EXPECT_EQ(test1_size, fd.write(test1_data, test1_size));
  }

  {
    auto reader_fd = openRWSharedFile(path, PF_OPEN_EXISTING | PF_READ);
    ASSERT_TRUE(reader_fd->isValid());

    std::vector<char> buf;
    buf.assign(test1_size, '\0');

    EXPECT_EQ(test1_size, reader_fd->read(buf.data(), test1_size));
    EXPECT_EQ(static_cast<size_t>(test1_size), buf.size());

    for (ssize_t i = 0; i < test1_size; i++) {
      EXPECT_EQ(test1_data[i], buf[i]);
    }

    PlatformFile fd(path, PF_OPEN_ALWAYS | PF_WRITE | PF_APPEND);
    EXPECT_TRUE(fd.isValid());
  }
}

TEST_F(FileOpsTests, test_fileIo) {
  TempFile tmp_file;
  std::string path = tmp_file.path();

  const char* expected_read = "AAAABBBBCCCCDDDD";
  const ssize_t expected_read_len = ::strlen(expected_read);
  const ssize_t expected_write_len = ::strlen(expected_read);
  const size_t expected_buf_size = ::strlen(expected_read);

  {
    PlatformFile fd(path, PF_CREATE_NEW | PF_WRITE);
    ASSERT_TRUE(fd.isValid());
    EXPECT_EQ(expected_write_len, fd.write(expected_read, expected_read_len));
  }

  {
    std::vector<char> buf(expected_read_len);
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_READ);
    ASSERT_TRUE(fd.isValid());
    ASSERT_FALSE(fd.isSpecialFile());
    EXPECT_EQ(expected_read_len, fd.read(buf.data(), expected_read_len));
    EXPECT_EQ(expected_buf_size, buf.size());
    for (ssize_t i = 0; i < expected_read_len; i++) {
      EXPECT_EQ(expected_read[i], buf[i]);
    }
  }
}

TEST_F(FileOpsTests, test_append) {
  TempFile tmp_file;
  std::string path = tmp_file.path();

  const char* test_data = "AAAABBBBCCCCDDDDD";
  const ssize_t test_size = ::strlen(test_data);
  const ssize_t test1_size = 7;
  const ssize_t test2_size = test_size - test1_size;

  {
    PlatformFile fd(path, PF_OPEN_ALWAYS | PF_WRITE | PF_APPEND);
    ASSERT_TRUE(fd.isValid());
    EXPECT_EQ(test1_size, fd.write(test_data, test1_size));
  }

  {
    PlatformFile fd(path, PF_OPEN_ALWAYS | PF_WRITE | PF_APPEND);
    ASSERT_TRUE(fd.isValid());
    EXPECT_EQ(test2_size, fd.write(&test_data[7], test2_size));
  }

  {
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_READ);
    ASSERT_TRUE(fd.isValid());

    std::vector<char> buf;
    buf.assign(test_size, '\0');
    EXPECT_EQ(test_size, fd.read(buf.data(), test_size));
    EXPECT_EQ(static_cast<size_t>(test_size), buf.size());

    for (ssize_t i = 0; i < test_size; i++) {
      EXPECT_EQ(test_data[i], buf[i]);
    }
  }
}

TEST_F(FileOpsTests, test_asyncIo) {
  TempFile tmp_file;
  std::string path = tmp_file.path();

  const char* expected = "AAAABBBBCCCCDDDDEEEEFFFFGGGG";
  const ssize_t expected_len = ::strlen(expected);

  {
    PlatformFile fd(path, PF_CREATE_NEW | PF_WRITE | PF_NONBLOCK);
    ASSERT_TRUE(fd.isValid());
    EXPECT_EQ(expected_len, fd.write(expected, expected_len));
  }

  {
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_READ | PF_NONBLOCK);
    ASSERT_TRUE(fd.isValid());
    ASSERT_FALSE(fd.isSpecialFile());

    std::vector<char> buf(expected_len);
    EXPECT_EQ(expected_len, fd.read(buf.data(), expected_len));
    EXPECT_EQ(0, ::memcmp(expected, buf.data(), expected_len));
  }

  {
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_READ | PF_NONBLOCK);
    ASSERT_TRUE(fd.isValid());
    ASSERT_FALSE(fd.isSpecialFile());

    std::vector<char> buf(expected_len);
    char* ptr = buf.data();
    ssize_t part_bytes = 0;
    int iterations = 0;
    do {
      part_bytes = fd.read(ptr, 4);
      if (part_bytes > 0) {
        ptr += part_bytes;
        iterations++;
      }
    } while (part_bytes > 0);

    EXPECT_EQ(7, iterations);
    EXPECT_EQ(0, ::memcmp(expected, buf.data(), expected_len));
  }
}

TEST_F(FileOpsTests, test_seekFile) {
  TempFile tmp_file;
  std::string path = tmp_file.path();

  const char* expected = "AABBBBAACCCAAAAADDDDAAAAAAAA";
  const ssize_t expected_len = ::strlen(expected);
  ssize_t expected_offs;

  {
    PlatformFile fd(path, PF_CREATE_ALWAYS | PF_WRITE);
    ASSERT_TRUE(fd.isValid());
    EXPECT_EQ(expected_len,
              fd.write("AAAAAAAAAAAAAAAAAAAAAAAAAAAA", expected_len));
  }

  // Cast to the proper type, off_t
  expected_offs = expected_len - 12;

  {
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_WRITE);
    ASSERT_TRUE(fd.isValid());

    EXPECT_EQ(expected_offs, fd.seek(-12, PF_SEEK_END));
    EXPECT_EQ(4, fd.write("DDDD", 4));

    EXPECT_EQ(2, fd.seek(2, PF_SEEK_BEGIN));
    EXPECT_EQ(4, fd.write("BBBB", 4));

    EXPECT_EQ(8, fd.seek(2, PF_SEEK_CURRENT));
    EXPECT_EQ(3, fd.write("CCC", 3));
  }

  {
    std::vector<char> buffer(expected_len);

    PlatformFile fd(path, PF_OPEN_EXISTING | PF_READ);
    ASSERT_TRUE(fd.isValid());

    EXPECT_EQ(expected_len, fd.read(buffer.data(), expected_len));
    EXPECT_EQ(0, ::memcmp(buffer.data(), expected, expected_len));
  }
}

TEST_F(FileOpsTests, test_large_read_write) {
  TempFile tmp_file;
  std::string path = tmp_file.path();

  const std::string expected(20000000, 'A');
  const ssize_t expected_len = expected.size();
  ASSERT_EQ(strnlen(expected.data(), 20000001), 20000000U);

  {
    PlatformFile fd(path, PF_CREATE_ALWAYS | PF_WRITE);
    ASSERT_TRUE(fd.isValid());
    auto write_len = fd.write(expected.c_str(), expected_len);
    EXPECT_EQ(expected_len, write_len);
  }

  {
    std::vector<char> buffer(expected_len);
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_READ);
    ASSERT_TRUE(fd.isValid());
    auto read_len = fd.read(buffer.data(), expected_len);
    EXPECT_EQ(expected_len, read_len);
    EXPECT_EQ(expected, std::string(buffer.data(), buffer.size()));
  }
}

TEST_F(FileOpsTests, test_chmod_no_exec) {
  TempFile tmp_file;
  std::string path = tmp_file.path();

  {
    PlatformFile fd(path, PF_CREATE_ALWAYS | PF_WRITE);
    ASSERT_TRUE(fd.isValid());
    EXPECT_EQ(4, fd.write("TEST", 4));
  }

  EXPECT_TRUE(platformChmod(path, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH));

  {
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_READ);
    ASSERT_TRUE(fd.isValid());

    auto status = fd.isExecutable();
    EXPECT_TRUE(!status.ok());
    EXPECT_EQ(1, status.getCode());
  }

  EXPECT_TRUE(platformChmod(
      path, S_IRUSR | S_IWUSR | S_IXUSR | S_IROTH | S_IWOTH | S_IXOTH));

  {
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_READ);
    ASSERT_TRUE(fd.isValid());

    EXPECT_TRUE(fd.isExecutable().ok());
  }
}

TEST_F(FileOpsTests, test_chmod_no_read) {
  TempFile tmp_file;
  std::string path = tmp_file.path();

  {
    PlatformFile fd(path, PF_CREATE_ALWAYS | PF_WRITE);
    ASSERT_TRUE(fd.isValid());
    EXPECT_EQ(4, fd.write("TEST", 4));
  }

  EXPECT_TRUE(platformChmod(path, S_IWUSR | S_IWOTH));

  {
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_READ);
    EXPECT_EQ(isUserPOSIXAdmin(), fd.isValid());
  }

  {
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_WRITE);
    EXPECT_TRUE(fd.isValid());
  }
}

TEST_F(FileOpsTests, test_chmod_no_write) {
  TempFile tmp_file;
  std::string path = tmp_file.path();

  {
    PlatformFile fd(path, PF_CREATE_ALWAYS | PF_WRITE);
    ASSERT_TRUE(fd.isValid());
    EXPECT_EQ(4, fd.write("TEST", 4));
  }

  EXPECT_TRUE(platformChmod(path, S_IRUSR | S_IROTH));

  {
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_READ);
    EXPECT_TRUE(fd.isValid());
  }

  {
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_WRITE);
    EXPECT_EQ(isUserPOSIXAdmin(), fd.isValid());
  }
}

TEST_F(FileOpsTests, test_access) {
  const int all_access = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP |
                         S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH;

  TempFile tmp_file;
  std::string path = tmp_file.path();

  {
    PlatformFile fd(path, PF_CREATE_ALWAYS | PF_WRITE);
    ASSERT_TRUE(fd.isValid());
    EXPECT_EQ(4, fd.write("TEST", 4));
  }

  EXPECT_TRUE(platformChmod(path, S_IRUSR | S_IWUSR | S_IXUSR));

  EXPECT_EQ(0, platformAccess(path, R_OK | W_OK | X_OK));
  EXPECT_EQ(0, platformAccess(path, R_OK | W_OK));
  EXPECT_EQ(0, platformAccess(path, R_OK | X_OK));
  EXPECT_EQ(0, platformAccess(path, W_OK | X_OK));
  EXPECT_EQ(0, platformAccess(path, R_OK));
  EXPECT_EQ(0, platformAccess(path, W_OK));
  EXPECT_EQ(0, platformAccess(path, X_OK));

  EXPECT_TRUE(platformChmod(path, S_IRUSR | S_IWUSR));

  EXPECT_EQ(-1, platformAccess(path, R_OK | W_OK | X_OK));
  EXPECT_EQ(0, platformAccess(path, R_OK | W_OK));
  EXPECT_EQ(-1, platformAccess(path, R_OK | X_OK));
  EXPECT_EQ(-1, platformAccess(path, W_OK | X_OK));
  EXPECT_EQ(0, platformAccess(path, R_OK));
  EXPECT_EQ(0, platformAccess(path, W_OK));
  EXPECT_EQ(-1, platformAccess(path, X_OK));

  EXPECT_TRUE(platformChmod(path, S_IRUSR | S_IXUSR));

  if (!isUserPOSIXAdmin()) {
    EXPECT_EQ(-1, platformAccess(path, R_OK | W_OK | X_OK));
    EXPECT_EQ(-1, platformAccess(path, R_OK | W_OK));
    EXPECT_EQ(0, platformAccess(path, R_OK | X_OK));
    EXPECT_EQ(-1, platformAccess(path, W_OK | X_OK));
    EXPECT_EQ(0, platformAccess(path, R_OK));
    EXPECT_EQ(-1, platformAccess(path, W_OK));
    EXPECT_EQ(0, platformAccess(path, X_OK));
  }

  EXPECT_TRUE(platformChmod(path, S_IWUSR | S_IXUSR));

  if (!isUserPOSIXAdmin()) {
    EXPECT_EQ(-1, platformAccess(path, R_OK | W_OK | X_OK));
    EXPECT_EQ(-1, platformAccess(path, R_OK | W_OK));
    EXPECT_EQ(-1, platformAccess(path, R_OK | X_OK));
    EXPECT_EQ(0, platformAccess(path, W_OK | X_OK));
    EXPECT_EQ(-1, platformAccess(path, R_OK));
    EXPECT_EQ(0, platformAccess(path, W_OK));
    EXPECT_EQ(0, platformAccess(path, X_OK));
  }

  EXPECT_TRUE(platformChmod(path, S_IRUSR));

  if (!isUserPOSIXAdmin()) {
    EXPECT_EQ(-1, platformAccess(path, R_OK | W_OK | X_OK));
    EXPECT_EQ(-1, platformAccess(path, R_OK | W_OK));
    EXPECT_EQ(-1, platformAccess(path, R_OK | X_OK));
    EXPECT_EQ(-1, platformAccess(path, W_OK | X_OK));
    EXPECT_EQ(0, platformAccess(path, R_OK));
    EXPECT_EQ(-1, platformAccess(path, W_OK));
    EXPECT_EQ(-1, platformAccess(path, X_OK));
  }

  EXPECT_TRUE(platformChmod(path, S_IWUSR));

  if (!isUserPOSIXAdmin()) {
    EXPECT_EQ(-1, platformAccess(path, R_OK | W_OK | X_OK));
    EXPECT_EQ(-1, platformAccess(path, R_OK | W_OK));
    EXPECT_EQ(-1, platformAccess(path, R_OK | X_OK));
    EXPECT_EQ(-1, platformAccess(path, W_OK | X_OK));
    EXPECT_EQ(-1, platformAccess(path, R_OK));
    EXPECT_EQ(0, platformAccess(path, W_OK));
    EXPECT_EQ(-1, platformAccess(path, X_OK));
  }

  EXPECT_TRUE(platformChmod(path, S_IXUSR));

  if (!isUserPOSIXAdmin()) {
    EXPECT_EQ(-1, platformAccess(path, R_OK | W_OK | X_OK));
    EXPECT_EQ(-1, platformAccess(path, R_OK | W_OK));
    EXPECT_EQ(-1, platformAccess(path, R_OK | X_OK));
    EXPECT_EQ(-1, platformAccess(path, W_OK | X_OK));
    EXPECT_EQ(-1, platformAccess(path, R_OK));
    EXPECT_EQ(-1, platformAccess(path, W_OK));
    EXPECT_EQ(0, platformAccess(path, X_OK));
  }

  // Reset permissions
  EXPECT_TRUE(platformChmod(path, all_access));
}

TEST_F(FileOpsTests, test_safe_permissions) {
  const auto root_dir =
      (fs::temp_directory_path() / "safe-perms-test").string();
  const auto temp_file = root_dir + "/test";
  const int all_access = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP |
                         S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH;

  fs::create_directories(root_dir);

  {
    PlatformFile fd(temp_file, PF_CREATE_ALWAYS | PF_WRITE);
    ASSERT_TRUE(fd.isValid());

    EXPECT_TRUE(
        platformChmod(temp_file, S_IRUSR | S_IWGRP | S_IROTH | S_IWOTH));
    EXPECT_TRUE(platformChmod(root_dir, S_IRUSR | S_IRGRP | S_IROTH));

    auto status = fd.hasSafePermissions();
    EXPECT_FALSE(status.ok());
    EXPECT_EQ(1, status.getCode());

    if (isPlatform(PlatformType::TYPE_POSIX)) {
      // On POSIX, chmod on a file requires +x on the parent directory
      EXPECT_TRUE(platformChmod(root_dir, all_access));
    }

    EXPECT_TRUE(platformChmod(temp_file, S_IRUSR | S_IRGRP | S_IROTH));
    EXPECT_TRUE(platformChmod(root_dir,
                              S_IRUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH));

    status = fd.hasSafePermissions();

    if (isPlatform(PlatformType::TYPE_WINDOWS)) {
      EXPECT_FALSE(status.ok());
      EXPECT_EQ(1, status.getCode());
    } else {
      // On POSIX, we only check to see if temp_file has S_IWOTH
      EXPECT_TRUE(status.ok());
    }

    if (isPlatform(PlatformType::TYPE_POSIX)) {
      // On POSIX, chmod on a file requires +x on the parent directory
      EXPECT_TRUE(platformChmod(root_dir, all_access));
    }

    EXPECT_TRUE(platformChmod(temp_file, S_IRUSR | S_IRGRP | S_IROTH));
    EXPECT_TRUE(platformChmod(root_dir, S_IRUSR | S_IRGRP | S_IWGRP | S_IROTH));

    status = fd.hasSafePermissions();

    if (isPlatform(PlatformType::TYPE_WINDOWS)) {
      EXPECT_FALSE(status.ok());
      EXPECT_EQ(1, status.getCode());
    } else {
      // On POSIX, we only check to see if temp_file has S_IWOTH
      EXPECT_TRUE(status.ok());
    }

    if (isPlatform(PlatformType::TYPE_POSIX)) {
      // On POSIX, chmod on a file requires +x on the parent directory
      EXPECT_TRUE(platformChmod(root_dir, all_access));
    }

    EXPECT_TRUE(platformChmod(temp_file, 0));
    EXPECT_TRUE(platformChmod(root_dir, 0));
    EXPECT_TRUE(fd.hasSafePermissions().ok());

    if (isPlatform(PlatformType::TYPE_POSIX)) {
      // On POSIX, chmod on a file requires +x on the parent directory
      EXPECT_TRUE(platformChmod(root_dir, all_access));
    }

    EXPECT_TRUE(platformChmod(temp_file, S_IRUSR | S_IRGRP | S_IROTH));
    EXPECT_TRUE(platformChmod(root_dir, S_IRUSR | S_IRGRP | S_IROTH));
    EXPECT_TRUE(fd.hasSafePermissions().ok());
  }

  EXPECT_TRUE(platformChmod(root_dir, all_access));
  EXPECT_TRUE(platformChmod(temp_file, all_access));

  fs::remove_all(root_dir);
}

TEST_F(FileOpsTests, test_glob) {
  {
    std::vector<fs::path> expected{kFakeDirectory + "/door.txt",
                                   kFakeDirectory + "/root.txt",
                                   kFakeDirectory + "/root2.txt",
                                   kFakeDirectory + "/roto.txt"};
    auto result = platformGlob(kFakeDirectory + "/*.txt");
    EXPECT_TRUE(globResultsMatch(result, expected));
  }

  {
    std::vector<fs::path> expected{kFakeDirectory + "/deep1/",
                                   kFakeDirectory + "/deep11/",
                                   kFakeDirectory + "/door.txt",
                                   kFakeDirectory + "/root.txt",
                                   kFakeDirectory + "/root2.txt",
                                   kFakeDirectory + "/roto.txt",
                                   kFakeDirectory + "/toplevel/"};
    auto result = platformGlob(kFakeDirectory + "/*");
    EXPECT_TRUE(globResultsMatch(result, expected));
  }

  {
    std::vector<fs::path> expected{kFakeDirectory + "/deep1/deep2/",
                                   kFakeDirectory + "/deep1/level1.txt",
                                   kFakeDirectory + "/deep11/deep2/",
                                   kFakeDirectory + "/deep11/level1.txt",
                                   kFakeDirectory + "/deep11/not_bash",
                                   kFakeDirectory + "/toplevel/secondlevel1/",
                                   kFakeDirectory + "/toplevel/secondlevel2/",
                                   kFakeDirectory + "/toplevel/secondlevel3/"};
    auto result = platformGlob(kFakeDirectory + "/*/*");
    EXPECT_TRUE(globResultsMatch(result, expected));
  }

  {
    std::vector<fs::path> expected{
        kFakeDirectory + "/deep1/deep2/level2.txt",
        kFakeDirectory + "/deep11/deep2/deep3/",
        kFakeDirectory + "/deep11/deep2/level2.txt",
        kFakeDirectory + "/toplevel/secondlevel3/thirdlevel1/",
    };
    auto result = platformGlob(kFakeDirectory + "/*/*/*");
    EXPECT_TRUE(globResultsMatch(result, expected));
  }

  {
    std::vector<fs::path> expected{kFakeDirectory + "/deep11/deep2/deep3/",
                                   kFakeDirectory + "/deep11/deep2/level2.txt"};
    auto result = platformGlob(kFakeDirectory + "/*11/*/*");
    EXPECT_TRUE(globResultsMatch(result, expected));
  }

  {
    std::vector<fs::path> expected{kFakeDirectory + "/deep1/",
                                   kFakeDirectory + "/root.txt"};
    auto result = platformGlob(kFakeDirectory + "/{deep,root}{1,.txt}");
    EXPECT_TRUE(globResultsMatch(result, expected));
  }

  {
    std::vector<fs::path> expected{kFakeDirectory + "/deep1/deep2/level2.txt",
                                   kFakeDirectory + "/deep11/deep2/deep3/",
                                   kFakeDirectory + "/deep11/deep2/level2.txt"};
    auto result = platformGlob(kFakeDirectory + "/*/deep2/*");
    EXPECT_TRUE(globResultsMatch(result, expected));
  }

  {
    std::vector<fs::path> expected{kFakeDirectory + "/deep1/deep2/",
                                   kFakeDirectory + "/deep1/level1.txt",
                                   kFakeDirectory + "/deep11/deep2/",
                                   kFakeDirectory + "/deep11/level1.txt",
                                   kFakeDirectory + "/deep11/not_bash"};
    auto result =
        platformGlob(kFakeDirectory + "/*/{deep2,level1,not_bash}{,.txt}");
    EXPECT_TRUE(globResultsMatch(result, expected));
  }
}

TEST_F(FileOpsTests, test_zero_permissions_file) {
  TempFile tmp_file;
  std::string path = tmp_file.path();

  const std::string expected_str = "0_permissions";
  const ssize_t expected_len = expected_str.size();

  // Setup file for testing
  PlatformFile fd(path, PF_CREATE_NEW | PF_READ | PF_WRITE);
  ASSERT_TRUE(fd.isValid());
  EXPECT_EQ(expected_len, fd.write(expected_str.c_str(), expected_len));
  EXPECT_TRUE(platformChmod(path, 0));

  // Test file
  EXPECT_TRUE(!fd.isExecutable().ok());

  std::vector<char> buf(expected_len);
  EXPECT_EQ(0, fd.read(buf.data(), expected_len));

  if (!isUserPOSIXAdmin()) {
    auto modes = {R_OK, W_OK, X_OK};
    for (auto& mode : modes) {
      EXPECT_EQ(-1, platformAccess(path, mode));
    }
    EXPECT_EQ(boost::none, platformFopen(path, "r"));
  }
}
}
