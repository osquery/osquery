/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <algorithm>
#include <fstream>

#include <stdio.h>
#include <sys/stat.h>

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>

#include <osquery/filesystem/filesystem.h>

#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/logger/logger.h>
#include <osquery/process/process.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/filesystem/mock_file_structure.h>

// Some proc* functions are only compiled when building on linux
#ifdef __linux__
#include "osquery/filesystem/linux/proc.h"
#endif

#ifdef WIN32
#include "winbase.h"
#include <osquery/utils/conversions/windows/strings.h>
#endif

namespace fs = boost::filesystem;

namespace osquery {

namespace {

const std::vector<std::string> kFileNameList{
    "辞書.txt",
    "test_file.txt",
};

}

DECLARE_uint64(read_max);

class FilesystemTests : public testing::Test {
 protected:
  fs::path test_working_dir_;
  fs::path fake_directory_;

  void SetUp() override {
    initializeFilesystemAPILocale();

    fake_directory_ = fs::canonical(createMockFileStructure());
    test_working_dir_ =
        fs::temp_directory_path() /
        fs::unique_path("osquery.test_working_dir.%%%%.%%%%");
    fs::create_directories(test_working_dir_);

    if (isPlatform(PlatformType::TYPE_WINDOWS)) {
      etc_hosts_path_ = "C:\\Windows\\System32\\drivers\\etc\\hosts";
      etc_path_ = "C:\\Windows\\System32\\drivers\\etc";
      tmp_path_ = fs::temp_directory_path().string();
      line_ending_ = "\r\n";

      auto raw_drive = getEnvVar("SystemDrive");
      system_root_ = (raw_drive.is_initialized() ? *raw_drive : "") + "\\";
    } else {
      etc_hosts_path_ = "/etc/hosts";
      etc_path_ = "/etc";
      tmp_path_ = "/tmp";
      line_ending_ = "\n";

      system_root_ = "/";
    }
  }

  void TearDown() override {
    fs::remove_all(fake_directory_);
    fs::remove_all(test_working_dir_);
  }

  /// Helper method to check if a path was included in results.
  bool contains(const std::vector<std::string>& all, const std::string& n) {
    return !(std::find(all.begin(), all.end(), n) == all.end());
  }

 protected:
  std::string etc_hosts_path_;
  std::string etc_path_;
  std::string tmp_path_;
  std::string system_root_;
  std::string line_ending_;
};

TEST_F(FilesystemTests, test_read_file) {
  for (const auto& file_name : kFileNameList) {
    auto file_path = test_working_dir_ / file_name;

    std::ofstream test_file(file_path.string());
    test_file.write("test123\n", sizeof("test123"));
    test_file.close();

    std::string content;
    auto s = readFile(file_path, content);

    EXPECT_TRUE(s.ok());
    EXPECT_EQ(s.toString(), "OK");
    EXPECT_EQ(content, "test123" + line_ending_);

    removePath(file_path);
  }
}

TEST_F(FilesystemTests, test_remove_path) {
  for (const auto& file_name : kFileNameList) {
    auto test_dir = test_working_dir_ / file_name;
    fs::create_directories(test_dir);

    auto test_file = test_working_dir_ / file_name / "rmfile";
    writeTextFile(test_file, "testcontent");

    ASSERT_TRUE(pathExists(test_file).ok());

    // Try to remove the directory.
    EXPECT_TRUE(removePath(test_dir));
    EXPECT_FALSE(pathExists(test_file).ok());
    EXPECT_FALSE(pathExists(test_dir).ok());
  }
}

TEST_F(FilesystemTests, test_write_file) {
  for (const auto& file_name : kFileNameList) {
    auto test_file = test_working_dir_ / file_name;
    std::string content(2048, 'A');

    EXPECT_TRUE(writeTextFile(test_file, content).ok());
    ASSERT_TRUE(pathExists(test_file).ok());
    ASSERT_TRUE(isWritable(test_file).ok());
    ASSERT_TRUE(removePath(test_file).ok());

    EXPECT_TRUE(writeTextFile(test_file, content, 0400));
    ASSERT_TRUE(pathExists(test_file).ok());

    // On POSIX systems, root can still read/write.
    EXPECT_FALSE(isWritable(test_file).ok());
    EXPECT_TRUE(isReadable(test_file).ok());
    ASSERT_TRUE(removePath(test_file).ok());

    EXPECT_TRUE(writeTextFile(test_file, content, 0000));
    ASSERT_TRUE(pathExists(test_file).ok());

    // On POSIX systems, root can still read/write.
    EXPECT_FALSE(isWritable(test_file).ok());
    EXPECT_FALSE(isReadable(test_file).ok());
    ASSERT_TRUE(removePath(test_file).ok());
  }
}

TEST_F(FilesystemTests, test_readwrite_file) {
  for (const auto& file_name : kFileNameList) {
    auto test_file = test_working_dir_ / file_name;
    size_t filesize = 4096 * 10;

    std::string in_content(filesize, 'A');
    EXPECT_TRUE(writeTextFile(test_file, in_content).ok());
    ASSERT_TRUE(pathExists(test_file).ok());
    ASSERT_TRUE(isReadable(test_file).ok());

    // Now read the content back.
    std::string out_content;
    EXPECT_TRUE(readFile(test_file, out_content).ok());
    EXPECT_EQ(filesize, out_content.size());
    EXPECT_EQ(in_content, out_content);
    removePath(test_file);

    // Now try to write outside of a 4k chunk size.
    in_content = std::string(filesize + 1, 'A');
    writeTextFile(test_file, in_content);
    out_content.clear();
    readFile(test_file, out_content);
    EXPECT_EQ(in_content, out_content);
    removePath(test_file);
  }
}

TEST_F(FilesystemTests, test_read_limit) {
  auto max = FLAGS_read_max;
  FLAGS_read_max = 3;
  std::string content;
  auto status = readFile(fake_directory_ / "root.txt", content);
  EXPECT_FALSE(status.ok());
  FLAGS_read_max = max;

  // Make sure non-link files are still readable.
  content.erase();
  status = readFile(fake_directory_ / "root.txt", content);
  EXPECT_TRUE(status.ok());

  // Any the links are readable too.
  status = readFile(fake_directory_ / "root2.txt", content);
  EXPECT_TRUE(status.ok());
}

TEST_F(FilesystemTests, test_read_size) {
  std::string content;
  size_t s = 3;
  auto status = readFile(fake_directory_ / "root.txt", content, s);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(content.size(), s);
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

  auto s = listFilesInDirectory(etc_path_, results);
  // This directory may be different on OS X or Linux.

  replaceGlobWildcards(etc_hosts_path_);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_TRUE(contains(results, etc_hosts_path_));
}

TEST_F(FilesystemTests, test_intermediate_globbing_directories) {
  fs::path thirdLevelDir =
      fs::path(fake_directory_) / kTopLevelMockFolderName / "%/thirdlevel1";
  std::vector<std::string> results;
  resolveFilePattern(thirdLevelDir, results);
  EXPECT_EQ(results.size(), 1U);
}

TEST_F(FilesystemTests, test_canonicalization) {
  std::string complex_path =
      (fs::path(fake_directory_) / "deep1/../deep1/..")
          .make_preferred()
          .string();
  std::string simple_path = fake_directory_.make_preferred().string();

  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    simple_path += "\\";
  } else {
    simple_path += "/";
  }

  // Use the inline wildcard and canonicalization replacement.
  // The 'simple_path' path contains a trailing '/', the replacement method will
  // distinguish between file and directory paths.
  replaceGlobWildcards(complex_path);
  EXPECT_EQ(simple_path, complex_path);

  // Now apply the same inline replacement on the simple_path directory and expect
  // no change to the comparison.
  replaceGlobWildcards(simple_path);
  EXPECT_EQ(simple_path, complex_path);

  // Now add a wildcard within the complex_path pattern. The replacement method
  // will not canonicalize past a '*' as the proceeding paths are limiters.
  complex_path = (fs::path(fake_directory_) / "*/deep2/../deep2/")
                .make_preferred()
                .string();
  replaceGlobWildcards(complex_path);
  EXPECT_EQ(complex_path,
            (fs::path(fake_directory_) / "*/deep2/../deep2/")
                .make_preferred()
                .string());
}

TEST_F(FilesystemTests, test_simple_globs) {
  std::vector<std::string> results;

  // Test the shell '*', we will support SQL's '%' too.
  auto status = resolveFilePattern(fake_directory_  / "*", results);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 7U);

  // Test the csh-style bracket syntax: {}.
  results.clear();
  resolveFilePattern(fake_directory_ / "{root,door}*", results);
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
  auto status = resolveFilePattern(fake_directory_ / "%", results, GLOB_ALL);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 7U);
  EXPECT_TRUE(contains(
      results,
      fs::path(fake_directory_ / "roto.txt").make_preferred().string()));
  EXPECT_TRUE(contains(
      results,
      fs::path(fake_directory_ / "deep11/").make_preferred().string()));
}

TEST_F(FilesystemTests, test_wildcard_single_files) {
  // Now list again with a restriction to only files.
  std::vector<std::string> results;
  resolveFilePattern(fake_directory_ / "%", results, GLOB_FILES);
  EXPECT_EQ(results.size(), 4U);
  EXPECT_TRUE(contains(
      results,
      fs::path(fake_directory_ / "roto.txt").make_preferred().string()));
}

TEST_F(FilesystemTests, test_wildcard_single_folders) {
  std::vector<std::string> results;
  resolveFilePattern(fake_directory_ / "%", results, GLOB_FOLDERS);
  EXPECT_EQ(results.size(), 3U);
  EXPECT_TRUE(contains(
      results,
      fs::path(fake_directory_ / "deep11/").make_preferred().string()));
}

TEST_F(FilesystemTests, test_wildcard_dual) {
  // Now test two directories deep with a single wildcard for each.
  std::vector<std::string> results;
  auto status = resolveFilePattern(fake_directory_ / "%/%", results);
  EXPECT_TRUE(status.ok());
  EXPECT_TRUE(contains(results,
                       fs::path(fake_directory_ / "deep1/level1.txt")
                           .make_preferred()
                           .string()));
}

TEST_F(FilesystemTests, test_wildcard_double) {
  // TODO: this will fail.
  std::vector<std::string> results;
  auto status = resolveFilePattern(fake_directory_ / "%%", results);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 20U);
  EXPECT_TRUE(contains(results,
                       fs::path(fake_directory_ / "deep1/deep2/level2.txt")
                           .make_preferred()
                           .string()));
}

TEST_F(FilesystemTests, test_wildcard_double_folders) {
  std::vector<std::string> results;
  resolveFilePattern(fake_directory_ / "%%", results, GLOB_FOLDERS);
  EXPECT_EQ(results.size(), 10U);
  EXPECT_TRUE(contains(results,
                       fs::path(fake_directory_ / "deep11/deep2/deep3/")
                           .make_preferred()
                           .string()));
}

TEST_F(FilesystemTests, test_wildcard_end_last_component) {
  std::vector<std::string> results;
  auto status = resolveFilePattern(fake_directory_ / "%11/%sh", results);
  EXPECT_TRUE(status.ok());
  EXPECT_TRUE(contains(
      results,
      fs::path(fake_directory_ / "deep11/not_bash").make_preferred().string()));
}

TEST_F(FilesystemTests, test_wildcard_middle_component) {
  std::vector<std::string> results;

  auto status = resolveFilePattern(fake_directory_ / "deep1%/%", results);

  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 5U);
  EXPECT_TRUE(contains(results,
                       fs::path(fake_directory_ / "deep1/level1.txt")
                           .make_preferred()
                           .string()));
  EXPECT_TRUE(contains(results,
                       fs::path(fake_directory_ / "deep11/level1.txt")
                           .make_preferred()
                           .string()));
}

TEST_F(FilesystemTests, test_wildcard_all_types) {
  std::vector<std::string> results;

  auto status = resolveFilePattern(fake_directory_ / "%p11/%/%%", results);
  EXPECT_TRUE(status.ok());
  EXPECT_TRUE(
      contains(results,
               fs::path(fake_directory_ / "deep11/deep2/deep3/level3.txt")
                   .make_preferred()
                   .string()));
}

TEST_F(FilesystemTests, test_wildcard_invalid_path) {
  std::vector<std::string> results;
  auto status = resolveFilePattern("/not_there_abcdefz/%%", results);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 0U);
}

TEST_F(FilesystemTests, test_wildcard_dotdot_files) {
  std::vector<std::string> results;
  auto status = resolveFilePattern(
      fake_directory_ / "deep11/deep2/../../%", results, GLOB_FILES);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 4U);

  // The response list will contain canonicalized versions: /tmp/<tests>/...
  std::string door_path =
      fs::path(fake_directory_ / "deep11/deep2/../../door.txt")
          .make_preferred()
          .string();
  replaceGlobWildcards(door_path);
  EXPECT_TRUE(contains(results, door_path));
}

TEST_F(FilesystemTests, test_no_wild) {
  std::vector<std::string> results;
  auto status =
      resolveFilePattern(fake_directory_ / "roto.txt", results, GLOB_FILES);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 1U);
  EXPECT_TRUE(contains(
      results,
      fs::path(fake_directory_ / "roto.txt").make_preferred().string()));
}

TEST_F(FilesystemTests, test_safe_permissions) {
  fs::path path_1(fake_directory_ / "door.txt");
  fs::path path_2(fake_directory_ / "deep11");

  // For testing we can request a different directory path.
  EXPECT_TRUE(safePermissions(system_root_, path_1));

  // A file with a directory.mode & 0x1000 fails.
  EXPECT_FALSE(safePermissions(tmp_path_, path_1));

  // A directory for a file will fail.
  EXPECT_FALSE(safePermissions(system_root_, path_2));

  // A root-owned file is appropriate
  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    EXPECT_TRUE(safePermissions("/", "/dev/zero"));
  }
}

// This will fail to link (procGetNamespaceInode) if we are not
// compiling on linux
#ifdef __linux__
TEST_F(FilesystemTests, test_user_namespace_parser) {
  auto unique_path = fs::temp_directory_path() /
                     fs::unique_path("osquery.tests.user_ns_parser.%%%%.%%%%");

  auto temp_path = unique_path.native();

  boost::system::error_code error_code;
  EXPECT_EQ(fs::create_directory(temp_path, error_code), true);

  auto symlink_path = temp_path + "/namespace";
  EXPECT_EQ(symlink("namespace:[112233]", symlink_path.data()), 0);

  ino_t namespace_inode;
  auto status = procGetNamespaceInode(namespace_inode, "namespace", temp_path);
  EXPECT_TRUE(status.ok());

  removePath(temp_path);
  EXPECT_EQ(namespace_inode, static_cast<ino_t>(112233));
}
#endif

TEST_F(FilesystemTests, test_read_proc) {
  std::string content;

  if (isPlatform(PlatformType::TYPE_LINUX)) {
    fs::path stat_path("/proc/" + std::to_string(platformGetPid()) + "/stat");
    EXPECT_TRUE(readFile(stat_path, content).ok());
    EXPECT_GT(content.size(), 0U);
  }
}

TEST_F(FilesystemTests, test_read_symlink) {
  std::string content;

  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    auto status = readFile(fake_directory_ / "root2.txt", content);
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(content, "root");
  }
}

TEST_F(FilesystemTests, test_read_zero) {
  std::string content;

  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    auto status = readFile("/dev/zero", content, 10);
    EXPECT_EQ(content.size(), 10U);
    for (size_t i = 0; i < 10; i++) {
      EXPECT_EQ(content[i], 0);
    }
  }
}

TEST_F(FilesystemTests, test_read_urandom) {
  std::string first, second;

  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    auto status = readFile("/dev/urandom", first, 10);
    EXPECT_TRUE(status.ok());
    status = readFile("/dev/urandom", second, 10);
    EXPECT_NE(first, second);
  }
}

TEST_F(FilesystemTests, create_directory) {
  auto const recursive = false;
  auto const ignore_existence = false;
  const auto tmp_path =
      fs::temp_directory_path() /
      fs::unique_path("osquery.tests.create_directory.%%%%.%%%%");
  ASSERT_FALSE(fs::exists(tmp_path));
  ASSERT_TRUE(createDirectory(tmp_path, recursive, ignore_existence).ok());
  ASSERT_TRUE(fs::exists(tmp_path));
  ASSERT_TRUE(fs::is_directory(tmp_path));
  ASSERT_FALSE(createDirectory(tmp_path).ok());
  fs::remove(tmp_path);
}

TEST_F(FilesystemTests, create_directory_without_parent) {
  auto const recursive = false;
  auto const ignore_existence = false;
  const auto tmp_root_path =
      fs::temp_directory_path() /
      fs::unique_path(
          "osquery.tests.create_directory_without_parent.%%%%.%%%%");
  ASSERT_FALSE(fs::exists(tmp_root_path));
  auto const tmp_path = tmp_root_path / "one_more";
  ASSERT_FALSE(fs::exists(tmp_path));
  ASSERT_FALSE(createDirectory(tmp_path, recursive, ignore_existence).ok());
  ASSERT_FALSE(fs::exists(tmp_path));
  ASSERT_FALSE(fs::is_directory(tmp_path));
  fs::remove_all(tmp_root_path);
}

TEST_F(FilesystemTests, create_directory_recursive) {
  auto const recursive = true;
  auto const ignore_existence = false;
  const auto tmp_root_path =
      fs::temp_directory_path() /
      fs::unique_path("osquery.tests.create_directory_recursive.%%%%.%%%%");
  ASSERT_FALSE(fs::exists(tmp_root_path));
  auto const tmp_path = tmp_root_path / "one_more";
  ASSERT_FALSE(fs::exists(tmp_path));
  ASSERT_TRUE(createDirectory(tmp_path, recursive, ignore_existence).ok());
  ASSERT_TRUE(fs::exists(tmp_path));
  ASSERT_TRUE(fs::is_directory(tmp_path));
  fs::remove_all(tmp_root_path);
}

TEST_F(FilesystemTests, create_directory_recursive_on_existing_dir) {
  auto const recursive = true;
  auto const ignore_existence = false;
  const auto tmp_root_path =
      fs::temp_directory_path() /
      fs::unique_path(
          "osquery.tests.create_directory_recursive_on_existing_dir.%%%%.%%%%");
  auto const tmp_path = tmp_root_path / "one_more";
  fs::create_directories(tmp_path);

  ASSERT_TRUE(fs::exists(tmp_path));
  ASSERT_TRUE(fs::is_directory(tmp_path));
  ASSERT_FALSE(createDirectory(tmp_path, recursive, ignore_existence).ok());
  ASSERT_TRUE(fs::exists(tmp_path));
  ASSERT_TRUE(fs::is_directory(tmp_path));
  fs::remove_all(tmp_root_path);
}

TEST_F(FilesystemTests, create_dir_recursive_ignore_existence) {
  auto const recursive = true;
  auto const ignore_existence = true;
  const auto tmp_root_path =
      fs::temp_directory_path() /
      fs::unique_path(
          "osquery.tests.create_dir_recursive_ignore_existence.%%%%.%%%%");
  auto const tmp_path = tmp_root_path / "one_more";
  fs::create_directories(tmp_path);

  ASSERT_TRUE(fs::exists(tmp_path));
  ASSERT_TRUE(fs::is_directory(tmp_path));
  ASSERT_TRUE(createDirectory(tmp_path, recursive, ignore_existence).ok());
  ASSERT_TRUE(fs::exists(tmp_path));
  ASSERT_TRUE(fs::is_directory(tmp_path));
  fs::remove_all(tmp_root_path);
}

TEST_F(FilesystemTests, test_read_empty_file) {
  auto test_file = test_working_dir_ / "fstests-empty";

  ASSERT_TRUE(writeTextFile(test_file, "").ok());
  ASSERT_TRUE(fs::is_empty(test_file));

  std::string content;
  ASSERT_TRUE(readFile(test_file, content));
  ASSERT_TRUE(content.empty());
}

TEST_F(FilesystemTests, test_read_fifo) {
  // This test verifies that open and read operations do not hang when using
  // non-blocking mode for pipes. Pipes are platform dependent, hence the
  // ifndef. Seems preferable to adding half-baked pipes to each fileops
  // implementation.
#ifndef WIN32
  auto test_file = test_working_dir_ / "fifo";
  ASSERT_EQ(::mkfifo(test_file.c_str(), S_IRUSR | S_IWUSR), 0);

  // The failure behavior is that this test will just hang forever, so
  // maybe it should be run in another thread with a timeout.
  std::string content;
  ASSERT_TRUE(readFile(test_file, content));
  ASSERT_TRUE(content.empty());
  ::unlink(test_file.c_str());
#else
  std::wstring pipe_name = stringToWstring("\\.pipe\test_pipe");
  HANDLE pipe_handle = CreateNamedPipe(pipe_name.c_str(),
                                       PIPE_ACCESS_DUPLEX,
                                       PIPE_WAIT,
                                       PIPE_UNLIMITED_INSTANCES,
                                       0,
                                       0,
                                       1000,
                                       0);
  std::string content;
  ASSERT_FALSE(readFile(pipe_name, content));
  ASSERT_TRUE(content.empty());
  CloseHandle(pipe_handle);
#endif
}

} // namespace osquery
