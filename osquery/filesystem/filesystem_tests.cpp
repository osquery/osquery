// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/filesystem.h"

#include <fstream>

#include <stdio.h>

#include <gtest/gtest.h>
#include <glog/logging.h>

namespace osquery {

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

TEST_F(FilesystemTests, test_list_files_in_directory_not_found) {
  std::vector<std::string> not_found_vector;
  auto not_found = listFilesInDirectory("/foo/bar", not_found_vector);
  EXPECT_FALSE(not_found.ok());
  EXPECT_EQ(not_found.toString(), "Directory not found");
}

TEST_F(FilesystemTests, test_list_files_in_directory_not_dir) {
  std::vector<std::string> not_dir_vector;
  auto not_dir = listFilesInDirectory("/etc/hosts", not_dir_vector);
  EXPECT_FALSE(not_dir.ok());
  EXPECT_EQ(not_dir.toString(), "Supplied path is not a directory");
}

TEST_F(FilesystemTests, test_list_files_in_directorty) {
  std::vector<std::string> results;
  auto s = listFilesInDirectory("/etc", results);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_NE(std::find(results.begin(), results.end(), "/etc/hosts"),
            results.end());
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
