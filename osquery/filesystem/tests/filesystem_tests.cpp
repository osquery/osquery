/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <algorithm>
#include <fstream>

#include <stdio.h>

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/system.h>

#include "osquery/core/process.h"
#include "osquery/tests/test_util.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {

DECLARE_uint64(read_max);
DECLARE_uint64(read_user_max);

#ifdef WIN32
auto raw_drive = getEnvVar("SystemDrive");

std::string kEtcHostsPath = "C:\\Windows\\System32\\drivers\\etc\\hosts";

const std::string kEtcPath = "C:\\Windows\\System32\\drivers\\etc";
const std::string kTmpPath = fs::temp_directory_path().string();
const std::string kSystemRoot =
    (raw_drive.is_initialized() ? *raw_drive : "") + "\\";
const std::string kLineEnding = "\r\n";
#else
std::string kEtcHostsPath = "/etc/hosts";

const std::string kEtcPath = "/etc";
const std::string kTmpPath = "/tmp";
const std::string kSystemRoot = "/";
const std::string kLineEnding = "\n";
#endif

std::string kDoorTxtPath;
std::string kDeep11Path;

class FilesystemTests : public testing::Test {
 protected:
  void SetUp() {
    createMockFileStructure();

    kDoorTxtPath =
        fs::path(kFakeDirectory + "/door.txt").make_preferred().string();
    kDeep11Path =
        fs::path(kFakeDirectory + "/deep11").make_preferred().string();
  }

  void TearDown() {
    tearDownMockFileStructure();
  }

  /// Helper method to check if a path was included in results.
  bool contains(const std::vector<std::string>& all, const std::string& n) {
    return !(std::find(all.begin(), all.end(), n) == all.end());
  }
};

TEST_F(FilesystemTests, test_read_file) {
  std::ofstream test_file(kTestWorkingDirectory + "fstests-file");
  test_file.write("test123\n", sizeof("test123"));
  test_file.close();

  std::string content;
  auto s = readFile(kTestWorkingDirectory + "fstests-file", content);

  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(content, "test123" + kLineEnding);

  remove(kTestWorkingDirectory + "fstests-file");
}

TEST_F(FilesystemTests, test_read_limit) {
  auto max = FLAGS_read_max;
  auto user_max = FLAGS_read_user_max;
  FLAGS_read_max = 3;
  std::string content;
  auto status = readFile(
      fs::path(kFakeDirectory + "/root.txt").make_preferred(), content);
  EXPECT_FALSE(status.ok());
  FLAGS_read_max = max;

  if (!isUserAdmin()) {
    content.erase();
    FLAGS_read_user_max = 2;
    status = readFile(kFakeDirectory + "/root.txt", content);
    EXPECT_FALSE(status.ok());
    FLAGS_read_user_max = user_max;

    // Make sure non-link files are still readable.
    content.erase();
    status = readFile(kFakeDirectory + "/root.txt", content);
    EXPECT_TRUE(status.ok());

    // Any the links are readable too.
    status = readFile(kFakeDirectory + "/root2.txt", content);
    EXPECT_TRUE(status.ok());
  }
}

TEST_F(FilesystemTests, test_list_files_missing_directory) {
  std::vector<std::string> results;
  auto status = listFilesInDirectory("/foo/bar", results);
  EXPECT_FALSE(status.ok());
}

TEST_F(FilesystemTests, test_list_files_invalid_directory) {
  std::vector<std::string> results;
  auto status = listFilesInDirectory("/etc/hosts", results);
  EXPECT_FALSE(status.ok());
}

TEST_F(FilesystemTests, test_list_files_valid_directory) {
  std::vector<std::string> results;

  auto s = listFilesInDirectory(kEtcPath, results);
  // This directory may be different on OS X or Linux.

  replaceGlobWildcards(kEtcHostsPath);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_TRUE(contains(results, kEtcHostsPath));
}

TEST_F(FilesystemTests, test_intermediate_globbing_directories) {
  fs::path thirdLevelDir =
      fs::path(kFakeDirectory) / "toplevel" / "%" / "thirdlevel1";
  std::vector<std::string> results;
  resolveFilePattern(thirdLevelDir, results);
  EXPECT_EQ(results.size(), 1U);
}

TEST_F(FilesystemTests, test_canonicalization) {
  std::string complex =
      (fs::path(kFakeDirectory) / "deep1" / ".." / "deep1" / "..")
          .make_preferred()
          .string();
  std::string simple =
      (fs::path(kFakeDirectory + "/")).make_preferred().string();

  // Use the inline wildcard and canonicalization replacement.
  // The 'simple' path contains a trailing '/', the replacement method will
  // distinguish between file and directory paths.
  replaceGlobWildcards(complex);
  EXPECT_EQ(simple, complex);

  // Now apply the same inline replacement on the simple directory and expect
  // no change to the comparison.
  replaceGlobWildcards(simple);
  EXPECT_EQ(simple, complex);

  // Now add a wildcard within the complex pattern. The replacement method
  // will not canonicalize past a '*' as the proceeding paths are limiters.
  complex = (fs::path(kFakeDirectory) / "*" / "deep2" / ".." / "deep2/")
                .make_preferred()
                .string();
  replaceGlobWildcards(complex);
  EXPECT_EQ(complex,
            (fs::path(kFakeDirectory) / "*" / "deep2" / ".." / "deep2/")
                .make_preferred()
                .string());
}

TEST_F(FilesystemTests, test_simple_globs) {
  std::vector<std::string> results;

  // Test the shell '*', we will support SQL's '%' too.
  auto status = resolveFilePattern(kFakeDirectory + "/*", results);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 7U);

  // Test the csh-style bracket syntax: {}.
  results.clear();
  resolveFilePattern(kFakeDirectory + "/{root,door}*", results);
  EXPECT_EQ(results.size(), 3U);

  // Test a tilde, home directory expansion, make no asserts about contents.
  results.clear();
  resolveFilePattern("~", results);
  if (results.size() == 0U) {
    LOG(WARNING) << "Tilde expansion failed";
  }
}

TEST_F(FilesystemTests, test_wildcard_single_all) {
  // Use '%' as a wild card to glob files within the temporarily-created dir.
  std::vector<std::string> results;
  auto status = resolveFilePattern(kFakeDirectory + "/%", results, GLOB_ALL);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 7U);
  EXPECT_TRUE(contains(
      results,
      fs::path(kFakeDirectory + "/roto.txt").make_preferred().string()));
  EXPECT_TRUE(contains(
      results,
      fs::path(kFakeDirectory + "/deep11/").make_preferred().string()));
}

TEST_F(FilesystemTests, test_wildcard_single_files) {
  // Now list again with a restriction to only files.
  std::vector<std::string> results;
  resolveFilePattern(kFakeDirectory + "/%", results, GLOB_FILES);
  EXPECT_EQ(results.size(), 4U);
  EXPECT_TRUE(contains(
      results,
      fs::path(kFakeDirectory + "/roto.txt").make_preferred().string()));
}

TEST_F(FilesystemTests, test_wildcard_single_folders) {
  std::vector<std::string> results;
  resolveFilePattern(kFakeDirectory + "/%", results, GLOB_FOLDERS);
  EXPECT_EQ(results.size(), 3U);
  EXPECT_TRUE(contains(
      results,
      fs::path(kFakeDirectory + "/deep11/").make_preferred().string()));
}

TEST_F(FilesystemTests, test_wildcard_dual) {
  // Now test two directories deep with a single wildcard for each.
  std::vector<std::string> results;
  auto status = resolveFilePattern(kFakeDirectory + "/%/%", results);
  EXPECT_TRUE(status.ok());
  EXPECT_TRUE(contains(results,
                       fs::path(kFakeDirectory + "/deep1/level1.txt")
                           .make_preferred()
                           .string()));
}

TEST_F(FilesystemTests, test_wildcard_double) {
  // TODO: this will fail.
  std::vector<std::string> results;
  auto status = resolveFilePattern(kFakeDirectory + "/%%", results);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 20U);
  EXPECT_TRUE(contains(results,
                       fs::path(kFakeDirectory + "/deep1/deep2/level2.txt")
                           .make_preferred()
                           .string()));
}

TEST_F(FilesystemTests, test_wildcard_double_folders) {
  std::vector<std::string> results;
  resolveFilePattern(kFakeDirectory + "/%%", results, GLOB_FOLDERS);
  EXPECT_EQ(results.size(), 10U);
  EXPECT_TRUE(contains(results,
                       fs::path(kFakeDirectory + "/deep11/deep2/deep3/")
                           .make_preferred()
                           .string()));
}

TEST_F(FilesystemTests, test_wildcard_end_last_component) {
  std::vector<std::string> results;
  auto status = resolveFilePattern(kFakeDirectory + "/%11/%sh", results);
  EXPECT_TRUE(status.ok());
  EXPECT_TRUE(contains(
      results,
      fs::path(kFakeDirectory + "/deep11/not_bash").make_preferred().string()));
}

TEST_F(FilesystemTests, test_wildcard_middle_component) {
  std::vector<std::string> results;

  auto status = resolveFilePattern(kFakeDirectory + "/deep1%/%", results);

  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 5U);
  EXPECT_TRUE(contains(results,
                       fs::path(kFakeDirectory + "/deep1/level1.txt")
                           .make_preferred()
                           .string()));
  EXPECT_TRUE(contains(results,
                       fs::path(kFakeDirectory + "/deep11/level1.txt")
                           .make_preferred()
                           .string()));
}

TEST_F(FilesystemTests, test_wildcard_all_types) {
  std::vector<std::string> results;

  auto status = resolveFilePattern(kFakeDirectory + "/%p11/%/%%", results);
  EXPECT_TRUE(status.ok());
  EXPECT_TRUE(
      contains(results,
               fs::path(kFakeDirectory + "/deep11/deep2/deep3/level3.txt")
                   .make_preferred()
                   .string()));
}

TEST_F(FilesystemTests, test_wildcard_invalid_path) {
  std::vector<std::string> results;
  auto status = resolveFilePattern("/not_ther_abcdefz/%%", results);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 0U);
}

TEST_F(FilesystemTests, test_wildcard_dotdot_files) {
  std::vector<std::string> results;
  auto status = resolveFilePattern(
      kFakeDirectory + "/deep11/deep2/../../%", results, GLOB_FILES);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 4U);

  // The response list will contain canonicalized versions: /tmp/<tests>/...
  std::string door_path =
      fs::path(kFakeDirectory + "/deep11/deep2/../../door.txt")
          .make_preferred()
          .string();
  replaceGlobWildcards(door_path);
  EXPECT_TRUE(contains(results, door_path));
}

TEST_F(FilesystemTests, test_dotdot_relative) {
  std::vector<std::string> results;
  auto status = resolveFilePattern(kTestDataPath + "%", results);
  EXPECT_TRUE(status.ok());

  bool found = false;
  for (const auto& file : results) {
    if (file.find("test.config")) {
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found);
}

TEST_F(FilesystemTests, test_no_wild) {
  std::vector<std::string> results;
  auto status =
      resolveFilePattern(kFakeDirectory + "/roto.txt", results, GLOB_FILES);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 1U);
  EXPECT_TRUE(contains(
      results,
      fs::path(kFakeDirectory + "/roto.txt").make_preferred().string()));
}

TEST_F(FilesystemTests, test_safe_permissions) {
  // For testing we can request a different directory path.
  EXPECT_TRUE(safePermissions(kSystemRoot, kDoorTxtPath));

  // A file with a directory.mode & 0x1000 fails.
  EXPECT_FALSE(safePermissions(kTmpPath, kDoorTxtPath));

  // A directory for a file will fail.
  EXPECT_FALSE(safePermissions(kSystemRoot, kDeep11Path));

#ifndef WIN32
  // A root-owned file is appropriate
  EXPECT_TRUE(safePermissions("/", "/dev/zero"));
#endif
}

#ifdef __linux__
TEST_F(FilesystemTests, test_read_proc) {
  std::string content;
  EXPECT_TRUE(readFile("/proc/" + std::to_string(getpid()) + "/stat", content));
  EXPECT_GT(content.size(), 0U);
}
#endif

#ifndef WIN32
TEST_F(FilesystemTests, test_read_symlink) {
  std::string content;
  auto status = readFile(kFakeDirectory + "/root2.txt", content);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(content, "root");
}

TEST_F(FilesystemTests, test_read_zero) {
  std::string content;
  auto status = readFile("/dev/zero", content, 10);
  EXPECT_EQ(content.size(), 10U);
  for (size_t i = 0; i < 10; i++) {
    EXPECT_EQ(content[i], 0);
  }
}

TEST_F(FilesystemTests, test_read_urandom) {
  std::string first, second;
  auto status = readFile("/dev/urandom", first, 10);
  EXPECT_TRUE(status.ok());
  status = readFile("/dev/urandom", second, 10);
  EXPECT_NE(first, second);
}
#endif
}
