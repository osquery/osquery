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

#include "osquery/core/test_util.h"
#include "osquery/filesystem/fileops.h"

#define EXPECT_GLOB_RESULT_MATCH(results, expected)                            \
  {                                                                            \
    EXPECT_EQ(results.size(), expected.size()) << "results count = "           \
                                               << results.size();              \
    if (results.size() == expected.size()) {                                   \
      size_t i = 0;                                                            \
      for (auto const& path : results) {                                       \
        EXPECT_EQ(path, expected[i].make_preferred().string());                \
        i++;                                                                   \
      }                                                                        \
    }                                                                          \
  }

namespace fs = boost::filesystem;

namespace osquery {

class FileOpsTests : public testing::Test {

  protected:
    void SetUp() {
      createMockFileStructure();
    }

    void TearDown() {
      tearDownMockFileStructure();
    }
};

TEST_F(FileOpsTests, test_openFile) {
  std::string path =
      (fs::temp_directory_path() / fs::unique_path()).make_preferred().string();

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

  fs::remove(path);
}

TEST_F(FileOpsTests, test_fileIo) {
  std::string path =
      (fs::temp_directory_path() / fs::unique_path()).make_preferred().string();
  const char *expected_read = "AAAABBBBCCCCDDDD";
  const int expected_read_len = ::strlen(expected_read);

  {
    PlatformFile fd(path, PF_CREATE_NEW | PF_WRITE);
    EXPECT_TRUE(fd.isValid());
    EXPECT_EQ(expected_read_len, fd.write(expected_read, expected_read_len));
  }

  {
    std::vector<char> buf(expected_read_len);
    PlatformFile fd(path, PF_OPEN_EXISTING | PF_READ);
    EXPECT_TRUE(fd.isValid());
    EXPECT_EQ(expected_read_len, fd.read(&buf[0], expected_read_len));
    EXPECT_EQ(expected_read_len, buf.size());
    for (size_t i = 0; i < expected_read_len; i++) {
      EXPECT_EQ(expected_read[i], buf[i]);
    }
  }

  fs::remove(path);
}

TEST_F(FileOpsTests, test_asyncIO) {

}

TEST_F(FileOpsTests, test_seekFile) {
  std::string path =
    (fs::temp_directory_path() / fs::unique_path()).make_preferred().string();

  fs::remove(path);
}

TEST_F(FileOpsTests, test_glob) {
  {
    std::vector<fs::path> expected{
      kFakeDirectory + "/door.txt",
      kFakeDirectory + "/root.txt",
      kFakeDirectory + "/root2.txt",
      kFakeDirectory + "/roto.txt"
    };
    auto result = platformGlob(kFakeDirectory + "/*.txt");
    EXPECT_GLOB_RESULT_MATCH(result, expected);
  }

  {
    std::vector<fs::path> expected{
      kFakeDirectory + "/deep1/",
      kFakeDirectory + "/deep11/",
      kFakeDirectory + "/door.txt",
      kFakeDirectory + "/root.txt",
      kFakeDirectory + "/root2.txt",
      kFakeDirectory + "/roto.txt"
    };
    auto result = platformGlob(kFakeDirectory + "/*");
    EXPECT_GLOB_RESULT_MATCH(result, expected);
  }

  {
    std::vector<fs::path> expected{
      kFakeDirectory + "/deep1/deep2/",
      kFakeDirectory + "/deep1/level1.txt",
      kFakeDirectory + "/deep11/deep2/",
      kFakeDirectory + "/deep11/level1.txt",
      kFakeDirectory + "/deep11/not_bash"
    };
    auto result = platformGlob(kFakeDirectory + "/*/*");
    EXPECT_GLOB_RESULT_MATCH(result, expected);
  }

  {
    std::vector<fs::path> expected{
      kFakeDirectory + "/deep1/deep2/level2.txt",
      kFakeDirectory + "/deep11/deep2/deep3/",
      kFakeDirectory + "/deep11/deep2/level2.txt"
    };
    auto result = platformGlob(kFakeDirectory + "/*/*/*");
    EXPECT_GLOB_RESULT_MATCH(result, expected);
  }

  {
    std::vector<fs::path> expected{
      kFakeDirectory + "/deep11/deep2/deep3/",
      kFakeDirectory + "/deep11/deep2/level2.txt"
    };
    auto result = platformGlob(kFakeDirectory + "/*11/*/*");
    EXPECT_GLOB_RESULT_MATCH(result, expected);
  }

  {
    std::vector<fs::path> expected{
      kFakeDirectory + "/deep1/",
      kFakeDirectory + "/root.txt"
    };
    auto result = platformGlob(kFakeDirectory + "/{deep,root}{1,.txt}");
    EXPECT_GLOB_RESULT_MATCH(result, expected);
  }

  {
    std::vector<fs::path> expected{
      kFakeDirectory + "/deep1/deep2/level2.txt",
      kFakeDirectory + "/deep11/deep2/deep3/",
      kFakeDirectory + "/deep11/deep2/level2.txt"
    };
    auto result = platformGlob(kFakeDirectory + "/*/deep2/*");
    EXPECT_GLOB_RESULT_MATCH(result, expected);
  }

  {
    std::vector<fs::path> expected{
      kFakeDirectory + "/deep1/deep2/",
      kFakeDirectory + "/deep1/level1.txt",
      kFakeDirectory + "/deep11/deep2/",
      kFakeDirectory + "/deep11/level1.txt",
      kFakeDirectory + "/deep11/not_bash"
    };
    auto result = platformGlob(kFakeDirectory + "/*/{deep2,level1,not_bash}{,.txt}");
    EXPECT_GLOB_RESULT_MATCH(result, expected);
  }
}

TEST_F(FileOpsTests, test_chmod) {

}
}
