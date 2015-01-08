/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>
#include <glog/logging.h>

#include <osquery/database.h>

#include "osquery/core/test_util.h"
#include "osquery/tables/system/darwin/filesystems.h"

using namespace osquery::core;

namespace osquery {
namespace tables {

class FilesystemsTests : public testing::Test {};

void setStatfsStrings(struct statfs* fs_info,
                      std::string fstypename,
                      std::string mntonname,
                      std::string mntfromname) {
  strlcpy(
      fs_info->f_fstypename, fstypename.c_str(), sizeof(fs_info->f_fstypename));
  strlcpy(
      fs_info->f_mntonname, mntonname.c_str(), sizeof(fs_info->f_mntonname));
  strlcpy(fs_info->f_mntfromname,
          mntfromname.c_str(),
          sizeof(fs_info->f_mntfromname));
}

TEST_F(FilesystemsTests, test_parse_statfs) {
  struct statfs fs_infos[3];
  int fs_count = 3;

  setStatfsStrings(&fs_infos[0], "foo", "bar", "baz");
  setStatfsStrings(&fs_infos[1], "womp", "womp", "wat");
  setStatfsStrings(&fs_infos[2], "hfs", "/", "/dev/disk1");

  QueryData result = parseStatfs(fs_infos, fs_count);

  Row r0{{"type", "foo"}, {"path", "bar"}, {"name", "baz"}};
  ASSERT_EQ(r0, result[0]);

  Row r1{{"type", "womp"}, {"path", "womp"}, {"name", "wat"}};
  ASSERT_EQ(r1, result[1]);

  Row r2{{"type", "hfs"}, {"path", "/"}, {"name", "/dev/disk1"}};
  ASSERT_EQ(r2, result[2]);
}

TEST_F(FilesystemsTests, test_gen_filesystems) {
  // We can't really verify too much here since we don't know what
  // filesystems will be present on the system running these tests
  QueryContext empty_context;

  QueryData result = genFilesystems(empty_context);

  ASSERT_LT(0, result.size());
}
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
