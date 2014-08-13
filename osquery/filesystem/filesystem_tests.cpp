// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/filesystem.h"

#include <fstream>

#include <stdio.h>

#include <gtest/gtest.h>
#include <glog/logging.h>

namespace osquery { namespace fs {

class FilesystemTests : public testing::Test {};

TEST_F(FilesystemTests, test_plugin) {
  std::ofstream test_file("/tmp/osquery-test-file");
  test_file.write("test123\n", sizeof("test123"));
  test_file.close();

  std::string content;
  auto s = readFile("/tmp/osquery-test-file", content);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(content, "test123\n");

  remove("/tmp/osquery-test-file");
}

}}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
