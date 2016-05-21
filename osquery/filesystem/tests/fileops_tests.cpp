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
    PlatformFile fd(path.c_str(), PF_OPEN_EXISTING | PF_READ);
    EXPECT_FALSE(fd.isValid());
  }

  {
    PlatformFile fd(path.c_str(), PF_CREATE_NEW | PF_WRITE);
    EXPECT_TRUE(fd.isValid());
  }

  {
    PlatformFile fd(path.c_str(), PF_CREATE_NEW | PF_READ);
    EXPECT_FALSE(fd.isValid());
  }

  fs::remove(path);

  {
    PlatformFile fd(path.c_str(), PF_CREATE_ALWAYS | PF_READ);
    EXPECT_TRUE(fd.isValid());
  }

  {
    PlatformFile fd(path.c_str(), PF_CREATE_ALWAYS | PF_READ);
    EXPECT_TRUE(fd.isValid());
  }

  {
    PlatformFile fd(path.c_str(), PF_OPEN_EXISTING | PF_READ);
    EXPECT_TRUE(fd.isValid());
  }

  fs::remove(path);
}

TEST_F(FileOpsTests, test_fileIo) {

}

TEST_F(FileOpsTests, test_asyncIO) {

}

TEST_F(FileOpsTests, test_seekFile) {

}

TEST_F(FileOpsTests, test_glob) {

}

TEST_F(FileOpsTests, test_chmod) {

}

}
