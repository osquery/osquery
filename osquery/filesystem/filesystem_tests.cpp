/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */


#include <fstream>

#include <stdio.h>

#include <gtest/gtest.h>

#include <boost/filesystem/operations.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>

namespace pt = boost::property_tree;

namespace osquery {

const std::string kFakeDirectory = "/tmp/osquery-fstests-pattern";
const std::string kFakeFile = "/tmp/osquery-fstests-pattern/file0";
const std::string kFakeSubFile = "/tmp/osquery-fstests-pattern/1/file1";
const std::string kFakeSubSubFile = "/tmp/osquery-fstests-pattern/1/2/file2";

class FilesystemTests : public testing::Test {

  void createFileAt(const std::string loc, const std::string content) {
  std::ofstream test_file(loc);
  test_file.write(content.c_str(), sizeof("test123"));
  test_file.close();
}


 protected:
  void SetUp() {
    boost::filesystem::create_directories(kFakeDirectory + "/deep11/deep2/deep3/");
    boost::filesystem::create_directories(kFakeDirectory + "/deep1/deep2/");

    createFileAt(kFakeDirectory + "/root.txt", "root");
    createFileAt(kFakeDirectory + "/toor.txt", "toor");
    createFileAt(kFakeDirectory + "/roto.txt", "roto");
    createFileAt(kFakeDirectory + "/deep1/level1.txt", "l1");
    createFileAt(kFakeDirectory + "/deep11/not_bash", "l1");
    createFileAt(kFakeDirectory + "/deep1/deep2/level2.txt", "l2");

    createFileAt(kFakeDirectory + "/deep11/level1.txt", "l1");
    createFileAt(kFakeDirectory + "/deep11/deep2/level2.txt", "l2");
    createFileAt(kFakeDirectory + "/deep11/deep2/deep3/level3.txt", "l3");
  }

  void TearDown() { boost::filesystem::remove_all(kFakeDirectory); }
};

TEST_F(FilesystemTests, test_plugin) {
  std::ofstream test_file("/tmp/osquery-fstests-file");
  test_file.write("test123\n", sizeof("test123"));
  test_file.close();

  std::string content;
  auto s = readFile("/tmp/osquery-fstests-file", content);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(content, "test123\n");

  remove("/tmp/osquery-fstests-file");
}

TEST_F(FilesystemTests, test_list_files_in_directory_not_found) {
  std::vector<std::string> not_found_vector;
  auto not_found = listFilesInDirectory("/foo/bar", not_found_vector);
  EXPECT_FALSE(not_found.ok());
  EXPECT_EQ(not_found.toString(), "Directory not found: /foo/bar");
}
TEST_F(FilesystemTests, test_wildcard_single_folder_list) {
  std::vector<std::string> files;
  auto status = resolveFilePattern(kFakeDirectory + "/%", files);
  EXPECT_TRUE(status.ok());
  EXPECT_NE(
      std::find(files.begin(), files.end(), kFakeDirectory + "/roto.txt"),
      files.end());
}

TEST_F(FilesystemTests, test_wildcard_dual) {
  std::vector<std::string> files;
  auto status = resolveFilePattern(kFakeDirectory + "/%/%", files);
  EXPECT_TRUE(status.ok());
  EXPECT_NE(std::find(files.begin(), files.end(),
                      kFakeDirectory + "/deep1/level1.txt"),
            files.end());
}

TEST_F(FilesystemTests, test_wildcard_full_recursion) {
  std::vector<std::string> files;
  auto status = resolveFilePattern(kFakeDirectory + "/%%", files);
  EXPECT_TRUE(status.ok());
  EXPECT_NE(std::find(files.begin(), files.end(),
                      kFakeDirectory + "/deep1/deep2/level2.txt"),
            files.end());
}

TEST_F(FilesystemTests, test_wildcard_end_last_component) {
  std::vector<std::string> files;
  auto status = resolveFilePattern(kFakeDirectory + "/%11/%sh", files);
  EXPECT_TRUE(status.ok());
  EXPECT_NE(std::find(files.begin(), files.end(),
                      kFakeDirectory + "/deep11/not_bash"),
            files.end());
}

TEST_F(FilesystemTests, test_wildcard_three_kinds) {
  std::vector<std::string> files;
  auto status = resolveFilePattern(kFakeDirectory + "/%p11/%/%%", files);
  EXPECT_TRUE(status.ok());
  EXPECT_NE(std::find(files.begin(), files.end(),
                      kFakeDirectory + "/deep11/deep2/deep3/level3.txt"),
            files.end());
}

TEST_F(FilesystemTests, test_wildcard_invalid_path) {
  std::vector<std::string> files;
  auto status = resolveFilePattern("/not_ther_abcdefz/%%", files);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(files.size(), 0);
}

TEST_F(FilesystemTests, test_wildcard_filewild) {
  std::vector<std::string> files;
  auto status = resolveFilePattern(kFakeDirectory + "/deep1%/%", files);
  EXPECT_TRUE(status.ok());
  EXPECT_NE(std::find(files.begin(), files.end(),
                      kFakeDirectory + "/deep1/level1.txt"),
            files.end());
  EXPECT_NE(std::find(files.begin(), files.end(),
                      kFakeDirectory + "/deep11/level1.txt"),
            files.end());
  boost::filesystem::remove_all(kFakeDirectory + "");
}

TEST_F(FilesystemTests, test_list_files_in_directory_not_dir) {
  std::vector<std::string> not_dir_vector;
  auto not_dir = listFilesInDirectory("/etc/hosts", not_dir_vector);
  EXPECT_FALSE(not_dir.ok());
  EXPECT_EQ(not_dir.toString(), "Supplied path is not a directory: /etc/hosts");
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
