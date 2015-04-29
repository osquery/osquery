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

#include <boost/property_tree/ptree.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/core/test_util.h"

namespace pt = boost::property_tree;

namespace osquery {
class FilesystemTests : public testing::Test {

 protected:
  void SetUp() { createMockFileStructure(); }

  void TearDown() { tearDownMockFileStructure(); }
};

TEST_F(FilesystemTests, test_plugin) {
  std::ofstream test_file(kTestWorkingDirectory + "fstests-file");
  test_file.write("test123\n", sizeof("test123"));
  test_file.close();

  std::string content;
  auto s = readFile(kTestWorkingDirectory + "fstests-file", content);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(content, "test123\n");

  remove(kTestWorkingDirectory + "fstests-file");
}

TEST_F(FilesystemTests, test_list_files_in_directory_not_found) {
  std::vector<std::string> not_found_vector;
  auto not_found = listFilesInDirectory("/foo/bar", not_found_vector);
  EXPECT_FALSE(not_found.ok());
  EXPECT_EQ(not_found.toString(), "Directory not found: /foo/bar");
}

TEST_F(FilesystemTests, test_wildcard_single_file_list) {
  std::vector<std::string> files;
  std::vector<std::string> files_flag;
  auto status = resolveFilePattern(kFakeDirectory + "/%", files);
  auto status2 =
      resolveFilePattern(kFakeDirectory + "/%", files_flag, REC_LIST_FILES);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(files.size(), 3);
  EXPECT_EQ(files.size(), files_flag.size());
  EXPECT_NE(std::find(files.begin(), files.end(), kFakeDirectory + "/roto.txt"),
            files.end());
}

TEST_F(FilesystemTests, test_wildcard_dual) {
  std::vector<std::string> files;
  auto status = resolveFilePattern(kFakeDirectory + "/%/%", files);
  EXPECT_TRUE(status.ok());
  EXPECT_NE(std::find(files.begin(),
                      files.end(),
                      kFakeDirectory + "/deep1/level1.txt"),
            files.end());
}

TEST_F(FilesystemTests, test_wildcard_full_recursion) {
  std::vector<std::string> files;
  auto status = resolveFilePattern(kFakeDirectory + "/%%", files);
  EXPECT_TRUE(status.ok());
  EXPECT_NE(std::find(files.begin(),
                      files.end(),
                      kFakeDirectory + "/deep1/deep2/level2.txt"),
            files.end());
}

TEST_F(FilesystemTests, test_wildcard_end_last_component) {
  std::vector<std::string> files;
  auto status = resolveFilePattern(kFakeDirectory + "/%11/%sh", files);
  EXPECT_TRUE(status.ok());
  EXPECT_NE(std::find(files.begin(),
                      files.end(),
                      kFakeDirectory + "/deep11/not_bash"),
            files.end());
}

TEST_F(FilesystemTests, test_wildcard_three_kinds) {
  std::vector<std::string> files;
  auto status = resolveFilePattern(kFakeDirectory + "/%p11/%/%%", files);
  EXPECT_TRUE(status.ok());
  EXPECT_NE(std::find(files.begin(),
                      files.end(),
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
  EXPECT_NE(std::find(files.begin(),
                      files.end(),
                      kFakeDirectory + "/deep1/level1.txt"),
            files.end());
  EXPECT_NE(std::find(files.begin(),
                      files.end(),
                      kFakeDirectory + "/deep11/level1.txt"),
            files.end());
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

TEST_F(FilesystemTests, test_wildcard_single_folder_list) {
  std::vector<std::string> folders;
  auto status =
      resolveFilePattern(kFakeDirectory + "/%", folders, REC_LIST_FOLDERS);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(folders.size(), 3);
  EXPECT_NE(
      std::find(folders.begin(), folders.end(), kFakeDirectory + "/deep11"),
      folders.end());
}

TEST_F(FilesystemTests, test_wildcard_single_all_list) {
  std::vector<std::string> all;
  auto status = resolveFilePattern(kFakeDirectory + "/%", all, REC_LIST_ALL);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(all.size(), 6);
  EXPECT_NE(std::find(all.begin(), all.end(), kFakeDirectory + "/roto.txt"),
            all.end());
  EXPECT_NE(std::find(all.begin(), all.end(), kFakeDirectory + "/deep11"),
            all.end());
}

TEST_F(FilesystemTests, test_wildcard_double_folders) {
  std::vector<std::string> all;
  auto status =
      resolveFilePattern(kFakeDirectory + "/%%", all, REC_LIST_FOLDERS);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(all.size(), 6);
  EXPECT_NE(std::find(all.begin(), all.end(), kFakeDirectory), all.end());
  EXPECT_NE(
      std::find(all.begin(), all.end(), kFakeDirectory + "/deep11/deep2/deep3"),
      all.end());
}

TEST_F(FilesystemTests, test_wildcard_double_all) {
  std::vector<std::string> all;
  auto status = resolveFilePattern(kFakeDirectory + "/%%", all, REC_LIST_ALL);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(all.size(), 15);
  EXPECT_NE(std::find(all.begin(), all.end(), kFakeDirectory + "/roto.txt"),
            all.end());
  EXPECT_NE(
      std::find(all.begin(), all.end(), kFakeDirectory + "/deep11/deep2/deep3"),
      all.end());
}
TEST_F(FilesystemTests, test_double_wild_event_opt) {
  std::vector<std::string> all;
  auto status = resolveFilePattern(
      kFakeDirectory + "/%%", all, REC_LIST_FOLDERS | REC_EVENT_OPT);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(all.size(), 1);
  EXPECT_NE(std::find(all.begin(), all.end(), kFakeDirectory), all.end());
}

TEST_F(FilesystemTests, test_letter_wild_opt) {
  std::vector<std::string> all;
  auto status = resolveFilePattern(
      kFakeDirectory + "/d%", all, REC_LIST_FOLDERS | REC_EVENT_OPT);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(all.size(), 3);
  EXPECT_NE(std::find(all.begin(), all.end(), kFakeDirectory + "/deep1"),
            all.end());
  EXPECT_NE(std::find(all.begin(), all.end(), kFakeDirectory + "/door.txt"),
            all.end());
}

TEST_F(FilesystemTests, test_dotdot) {
  std::vector<std::string> all;
  auto status = resolveFilePattern(
      kFakeDirectory + "/deep11/deep2/../../%", all, REC_LIST_FILES);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(all.size(), 3);
  EXPECT_NE(std::find(all.begin(),
                      all.end(),
                      kFakeDirectory + "/deep11/deep2/../../door.txt"),
            all.end());
}

TEST_F(FilesystemTests, test_dotdot_relative) {
  std::vector<std::string> all;
  auto status = resolveFilePattern(kTestDataPath + "%", all, REC_LIST_ALL);
  EXPECT_TRUE(status.ok());

  bool found = false;
  for (const auto& file : all) {
    if (file.find("test.config")) {
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found);
}

TEST_F(FilesystemTests, test_no_wild) {
  std::vector<std::string> all;
  auto status =
      resolveFilePattern(kFakeDirectory + "/roto.txt", all, REC_LIST_FILES);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(all.size(), 1);
  EXPECT_NE(std::find(all.begin(), all.end(), kFakeDirectory + "/roto.txt"),
            all.end());
}

TEST_F(FilesystemTests, test_safe_permissions) {
  // For testing we can request a different directory path.
  EXPECT_TRUE(safePermissions("/", kFakeDirectory + "/door.txt"));
  // A file with a directory.mode & 0x1000 fails.
  EXPECT_FALSE(safePermissions("/tmp", kFakeDirectory + "/door.txt"));
  // A directory for a file will fail.
  EXPECT_FALSE(safePermissions("/", kFakeDirectory + "/deep11"));
  // A root-owned file is appropriate
  EXPECT_TRUE(safePermissions("/", "/dev/zero"));
}
}
