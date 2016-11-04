/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
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
                        std::vector<fs::path>& expected) {
    if (results.size() == expected.size()) {
      size_t i = 0;
      for (auto const& path : results) {
        if (path != expected[i].make_preferred().string()) {
          return false;
        }
        i++;
      }

      return true;
    }

    return false;
  }
};

class TempFile {
 public:
  TempFile()
      : path_((fs::temp_directory_path() / fs::unique_path())
                  .make_preferred()
                  .string()) {}

  ~TempFile() {
    if (fs::exists(path_)) {
      fs::remove(path_);
    }
  }

  const std::string& path() const {
    return path_;
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

TEST_F(FileOpsTests, test_shareRead) {
  TempFile tmp_file;
  std::string path = tmp_file.path();

  const char* test1_data = "AAAABBBB";
  const ssize_t test1_size = ::strlen(test1_data);

  {
    PlatformFile fd(path, PF_CREATE_NEW | PF_WRITE);
    EXPECT_TRUE(fd.isValid());
    EXPECT_EQ(test1_size, fd.write(test1_data, test1_size));
  }

  {
    auto reader_fd = openRWSharedFile(path, PF_OPEN_EXISTING | PF_READ);
    EXPECT_TRUE(reader_fd->isValid());

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
    EXPECT_TRUE(fd.isValid());
    EXPECT_EQ(expected_write_len, fd.write(expected_read, expected_read_len));
  }

  {
    std::vector<char> buf(expected_read_len);
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_READ);
    EXPECT_TRUE(fd.isValid());
    EXPECT_FALSE(fd.isSpecialFile());
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
    EXPECT_TRUE(fd.isValid());
    EXPECT_EQ(test1_size, fd.write(test_data, test1_size));
  }

  {
    PlatformFile fd(path, PF_OPEN_ALWAYS | PF_WRITE | PF_APPEND);
    EXPECT_TRUE(fd.isValid());
    EXPECT_EQ(test2_size, fd.write(&test_data[7], test2_size));
  }

  {
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_READ);
    EXPECT_TRUE(fd.isValid());

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
    EXPECT_TRUE(fd.isValid());
    EXPECT_EQ(expected_len, fd.write(expected, expected_len));
  }

  {
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_READ | PF_NONBLOCK);
    EXPECT_TRUE(fd.isValid());
    EXPECT_FALSE(fd.isSpecialFile());

    std::vector<char> buf(expected_len);
    EXPECT_EQ(expected_len, fd.read(buf.data(), expected_len));
    EXPECT_EQ(0, ::memcmp(expected, buf.data(), expected_len));
  }

  {
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_READ | PF_NONBLOCK);
    EXPECT_TRUE(fd.isValid());
    EXPECT_FALSE(fd.isSpecialFile());

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
    EXPECT_TRUE(fd.isValid());
    EXPECT_EQ(expected_len,
              fd.write("AAAAAAAAAAAAAAAAAAAAAAAAAAAA", expected_len));
  }

  // Cast to the proper type, off_t
  expected_offs = expected_len - 12;

  {
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_WRITE);
    EXPECT_TRUE(fd.isValid());

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
    EXPECT_TRUE(fd.isValid());

    EXPECT_EQ(expected_len, fd.read(buffer.data(), expected_len));
    EXPECT_EQ(0, ::memcmp(buffer.data(), expected, expected_len));
  }
}

TEST_F(FileOpsTests, test_large_read_write) {
  TempFile tmp_file;
  std::string path = tmp_file.path();

  const std::string expected(600000000, 'A');
  const ssize_t expected_len = expected.size();

  {
    PlatformFile fd(path, PF_CREATE_ALWAYS | PF_WRITE);
    EXPECT_TRUE(fd.isValid());
    auto write_len = fd.write(expected.c_str(), expected_len);
    EXPECT_EQ(expected_len, write_len);
  }

  {
    std::vector<char> buffer(expected_len);
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_READ);
    EXPECT_TRUE(fd.isValid());
    auto read_len = fd.read(buffer.data(), expected_len);
    EXPECT_EQ(expected_len, read_len);
    EXPECT_EQ(expected, std::string(buffer.data()));
  }
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
    std::vector<fs::path> expected;
    if (isPlatform(PlatformType::TYPE_WINDOWS)) {
      expected = {kFakeDirectory + "/deep1/deep2/",
                  kFakeDirectory + "/deep1/level1.txt",
                  kFakeDirectory + "/deep11/deep2/",
                  kFakeDirectory + "/deep11/level1.txt",
                  kFakeDirectory + "/deep11/not_bash"};
    } else {
      expected = {kFakeDirectory + "/deep1/deep2/",
                  kFakeDirectory + "/deep11/deep2/",
                  kFakeDirectory + "/deep1/level1.txt",
                  kFakeDirectory + "/deep11/level1.txt",
                  kFakeDirectory + "/deep11/not_bash"};
    }

    auto result =
        platformGlob(kFakeDirectory + "/*/{deep2,level1,not_bash}{,.txt}");
    EXPECT_TRUE(globResultsMatch(result, expected));
  }
}
}
