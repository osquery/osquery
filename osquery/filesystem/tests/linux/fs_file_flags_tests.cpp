/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <fstream>

#include <boost/filesystem.hpp>

#include <gtest/gtest.h>

#include <linux/fs.h>

#include <osquery/filesystem/fileops.h>
#include <osquery/utils/scope_guard.h>

// Same fallback definitions as fs_file_flags.cpp: the build must not depend
// on the age of the sysroot's kernel headers.
#ifndef FS_IOC_GETFLAGS
#define FS_IOC_GETFLAGS _IOR('f', 1, long)
#endif
#ifndef FS_IOC_SETFLAGS
#define FS_IOC_SETFLAGS _IOW('f', 2, long)
#endif
#ifndef FS_SECRM_FL
#define FS_SECRM_FL 0x00000001
#endif
#ifndef FS_UNRM_FL
#define FS_UNRM_FL 0x00000002
#endif
#ifndef FS_COMPR_FL
#define FS_COMPR_FL 0x00000004
#endif
#ifndef FS_SYNC_FL
#define FS_SYNC_FL 0x00000008
#endif
#ifndef FS_IMMUTABLE_FL
#define FS_IMMUTABLE_FL 0x00000010
#endif
#ifndef FS_APPEND_FL
#define FS_APPEND_FL 0x00000020
#endif
#ifndef FS_NODUMP_FL
#define FS_NODUMP_FL 0x00000040
#endif
#ifndef FS_NOATIME_FL
#define FS_NOATIME_FL 0x00000080
#endif
#ifndef FS_DIRTY_FL
#define FS_DIRTY_FL 0x00000100
#endif
#ifndef FS_COMPRBLK_FL
#define FS_COMPRBLK_FL 0x00000200
#endif
#ifndef FS_NOCOMP_FL
#define FS_NOCOMP_FL 0x00000400
#endif
#ifndef FS_ENCRYPT_FL
#define FS_ENCRYPT_FL 0x00000800
#endif
#ifndef FS_INDEX_FL
#define FS_INDEX_FL 0x00001000
#endif
#ifndef FS_IMAGIC_FL
#define FS_IMAGIC_FL 0x00002000
#endif
#ifndef FS_JOURNAL_DATA_FL
#define FS_JOURNAL_DATA_FL 0x00004000
#endif
#ifndef FS_NOTAIL_FL
#define FS_NOTAIL_FL 0x00008000
#endif
#ifndef FS_DIRSYNC_FL
#define FS_DIRSYNC_FL 0x00010000
#endif
#ifndef FS_TOPDIR_FL
#define FS_TOPDIR_FL 0x00020000
#endif
#ifndef FS_HUGE_FILE_FL
#define FS_HUGE_FILE_FL 0x00040000
#endif
#ifndef FS_EXTENT_FL
#define FS_EXTENT_FL 0x00080000
#endif
#ifndef FS_VERITY_FL
#define FS_VERITY_FL 0x00100000
#endif
#ifndef FS_EA_INODE_FL
#define FS_EA_INODE_FL 0x00200000
#endif
#ifndef FS_EOFBLOCKS_FL
#define FS_EOFBLOCKS_FL 0x00400000
#endif
#ifndef FS_NOCOW_FL
#define FS_NOCOW_FL 0x00800000
#endif
#ifndef FS_DAX_FL
#define FS_DAX_FL 0x02000000
#endif
#ifndef FS_INLINE_DATA_FL
#define FS_INLINE_DATA_FL 0x10000000
#endif
#ifndef FS_PROJINHERIT_FL
#define FS_PROJINHERIT_FL 0x20000000
#endif
#ifndef FS_CASEFOLD_FL
#define FS_CASEFOLD_FL 0x40000000
#endif

namespace fs = boost::filesystem;

namespace osquery {
namespace {
class LinuxFsFileFlags : public testing::Test {
 protected:
  void SetUp() override {
    path_ = fs::temp_directory_path() /
            fs::unique_path("osquery.fs_file_flags_tests.%%%%-%%%%");

    std::ofstream output(path_.string());
    output << "test";
  }

  void TearDown() override {
    fs::remove(path_);
  }

  fs::path path_;
};

TEST_F(LinuxFsFileFlags, testAllFlags) {
  auto flags = FS_SECRM_FL | FS_UNRM_FL | FS_COMPR_FL | FS_SYNC_FL |
               FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NODUMP_FL | FS_NOATIME_FL |
               FS_DIRTY_FL | FS_COMPRBLK_FL | FS_NOCOMP_FL | FS_ENCRYPT_FL |
               FS_INDEX_FL | FS_IMAGIC_FL | FS_JOURNAL_DATA_FL | FS_NOTAIL_FL |
               FS_DIRSYNC_FL | FS_TOPDIR_FL | FS_HUGE_FILE_FL | FS_EXTENT_FL |
               FS_VERITY_FL | FS_EA_INODE_FL | FS_EOFBLOCKS_FL | FS_NOCOW_FL |
               FS_DAX_FL | FS_INLINE_DATA_FL | FS_PROJINHERIT_FL |
               FS_CASEFOLD_FL;

  std::string expected_description =
      "FS_SECRM_FL, FS_UNRM_FL, FS_COMPR_FL, FS_SYNC_FL, FS_IMMUTABLE_FL, "
      "FS_APPEND_FL, FS_NODUMP_FL, FS_NOATIME_FL, FS_DIRTY_FL, "
      "FS_COMPRBLK_FL, FS_NOCOMP_FL, FS_ENCRYPT_FL, FS_INDEX_FL, "
      "FS_IMAGIC_FL, FS_JOURNAL_DATA_FL, FS_NOTAIL_FL, FS_DIRSYNC_FL, "
      "FS_TOPDIR_FL, FS_HUGE_FILE_FL, FS_EXTENT_FL, FS_VERITY_FL, "
      "FS_EA_INODE_FL, FS_EOFBLOCKS_FL, FS_NOCOW_FL, FS_DAX_FL, "
      "FS_INLINE_DATA_FL, FS_PROJINHERIT_FL, FS_CASEFOLD_FL";

  // The function should return true when there are no undocumented bits
  // set inside the `flags` value
  std::string description;
  auto s = describeFilesystemFileFlags(description, flags);
  EXPECT_TRUE(s);

  EXPECT_EQ(description, expected_description);
}

TEST_F(LinuxFsFileFlags, foreignFlags) {
  auto flags = FS_IMMUTABLE_FL | FS_APPEND_FL | 0x01000000U;
  std::string expected_description =
      "FS_IMMUTABLE_FL, FS_APPEND_FL, 0x01000000";

  // The function should return false when there are undocumented bits used
  // in the `flags` value
  std::string description;
  auto s = describeFilesystemFileFlags(description, flags);
  EXPECT_FALSE(s);

  EXPECT_EQ(description, expected_description);
}

TEST_F(LinuxFsFileFlags, readFlagsOfRealFile) {
  std::uint32_t flags = 0U;
  auto status = getFilesystemFileFlags(path_.string(), flags);
  if (!status.ok()) {
    GTEST_SKIP() << "The filesystem of " << path_
                 << " does not support FS_IOC_GETFLAGS";
  }

  // A new file has no attribute flags set, except on ext4, which creates
  // regular files with FS_EXTENT_FL (extents) set
  EXPECT_EQ(flags & ~FS_EXTENT_FL, 0U);

  std::string description;
  EXPECT_TRUE(describeFilesystemFileFlags(description, flags));
  if ((flags & FS_EXTENT_FL) != 0U) {
    EXPECT_EQ(description, "FS_EXTENT_FL");
  } else {
    EXPECT_TRUE(description.empty());
  }
}

TEST_F(LinuxFsFileFlags, setAndReadNoDump) {
  auto fd = ::open(path_.c_str(), O_RDONLY | O_NONBLOCK);
  ASSERT_GE(fd, 0);
  auto fd_guard = scope_guard::create([fd]() { ::close(fd); });

  // NODUMP can be set by the file owner without special capabilities, on the
  // filesystems that support attribute flags at all
  int raw_flags = 0;
  if (::ioctl(fd, FS_IOC_GETFLAGS, &raw_flags) != 0) {
    GTEST_SKIP() << "The filesystem of " << path_
                 << " does not support FS_IOC_GETFLAGS";
  }

  auto updated_flags = raw_flags | FS_NODUMP_FL;
  if (::ioctl(fd, FS_IOC_SETFLAGS, &updated_flags) != 0) {
    GTEST_SKIP() << "The filesystem of " << path_
                 << " does not support FS_IOC_SETFLAGS";
  }

  std::uint32_t flags = 0U;
  ASSERT_TRUE(getFilesystemFileFlags(path_.string(), flags).ok());
  EXPECT_EQ(flags & FS_NODUMP_FL, FS_NODUMP_FL);

  std::string description;
  EXPECT_TRUE(describeFilesystemFileFlags(description, flags));
  EXPECT_EQ(description, "FS_NODUMP_FL");
}
} // namespace
} // namespace osquery
