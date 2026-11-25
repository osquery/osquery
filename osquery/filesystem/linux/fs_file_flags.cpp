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
#include <sys/stat.h>
#include <unistd.h>

#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <boost/algorithm/string/join.hpp>

#include <osquery/filesystem/fileops.h>
#include <osquery/utils/scope_guard.h>

// The FS_IOC_GETFLAGS ioctl and the FS_*_FL bits are the stable filesystem
// attribute ABI behind chattr(1)/lsattr(1), supported by ext4, XFS, Btrfs,
// tmpfs and others. <linux/fs.h> provides them, but any missing ones are
// defined here so the build does not depend on the sysroot header's age.
#include <linux/fs.h>

#ifndef FS_IOC_GETFLAGS
#define FS_IOC_GETFLAGS _IOR('f', 1, long)
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

namespace osquery {
namespace {
/// The list of supported flags, as documented in `man 1 chattr`
/// and in https://github.com/torvalds/linux/blob/master/include/uapi/linux/fs.h
const std::map<std::uint32_t, std::string> kFsFlagMap = {
    {FS_SECRM_FL, "FS_SECRM_FL"}, // 0x00000001
    {FS_UNRM_FL, "FS_UNRM_FL"}, // 0x00000002
    {FS_COMPR_FL, "FS_COMPR_FL"}, // 0x00000004
    {FS_SYNC_FL, "FS_SYNC_FL"}, // 0x00000008
    {FS_IMMUTABLE_FL, "FS_IMMUTABLE_FL"}, // 0x00000010
    {FS_APPEND_FL, "FS_APPEND_FL"}, // 0x00000020
    {FS_NODUMP_FL, "FS_NODUMP_FL"}, // 0x00000040
    {FS_NOATIME_FL, "FS_NOATIME_FL"}, // 0x00000080
    {FS_DIRTY_FL, "FS_DIRTY_FL"}, // 0x00000100
    {FS_COMPRBLK_FL, "FS_COMPRBLK_FL"}, // 0x00000200
    {FS_NOCOMP_FL, "FS_NOCOMP_FL"}, // 0x00000400
    {FS_ENCRYPT_FL, "FS_ENCRYPT_FL"}, // 0x00000800
    {FS_INDEX_FL, "FS_INDEX_FL"}, // 0x00001000
    {FS_IMAGIC_FL, "FS_IMAGIC_FL"}, // 0x00002000
    {FS_JOURNAL_DATA_FL, "FS_JOURNAL_DATA_FL"}, // 0x00004000
    {FS_NOTAIL_FL, "FS_NOTAIL_FL"}, // 0x00008000
    {FS_DIRSYNC_FL, "FS_DIRSYNC_FL"}, // 0x00010000
    {FS_TOPDIR_FL, "FS_TOPDIR_FL"}, // 0x00020000
    {FS_HUGE_FILE_FL, "FS_HUGE_FILE_FL"}, // 0x00040000
    {FS_EXTENT_FL, "FS_EXTENT_FL"}, // 0x00080000
    {FS_VERITY_FL, "FS_VERITY_FL"}, // 0x00100000
    {FS_EA_INODE_FL, "FS_EA_INODE_FL"}, // 0x00200000
    {FS_EOFBLOCKS_FL, "FS_EOFBLOCKS_FL"}, // 0x00400000
    {FS_NOCOW_FL, "FS_NOCOW_FL"}, // 0x00800000
    {FS_DAX_FL, "FS_DAX_FL"}, // 0x02000000
    {FS_INLINE_DATA_FL, "FS_INLINE_DATA_FL"}, // 0x10000000
    {FS_PROJINHERIT_FL, "FS_PROJINHERIT_FL"}, // 0x20000000
    {FS_CASEFOLD_FL, "FS_CASEFOLD_FL"}, // 0x40000000
};

std::uint32_t getFsFlagMask() {
  std::uint32_t result = 0U;

  for (const auto& p : kFsFlagMap) {
    const auto& bit = p.first;
    result |= bit;
  }

  return result;
}
} // namespace

Status getFilesystemFileFlags(const std::string& path, std::uint32_t& flags) {
  flags = 0U;

  // Only regular files and directories have attribute flags, and opening
  // anything else can have side effects: a device driver's open handler runs
  // even with O_NONBLOCK. So pin the path with an O_PATH descriptor, which
  // does not open the file itself, check its type, and only then open it,
  // through /proc/self/fd so that the check and the open see the same file.
  // Like a normal open, O_PATH follows symlinks.
  auto path_fd = ::open(path.c_str(), O_PATH | O_CLOEXEC);
  if (path_fd < 0) {
    return Status::failure("Failed to open file: " + path);
  }

  auto path_fd_guard = scope_guard::create([path_fd]() { ::close(path_fd); });

  struct stat file_stat;
  if (::fstat(path_fd, &file_stat) != 0) {
    return Status::failure("Failed to stat file: " + path);
  }

  if (!S_ISREG(file_stat.st_mode) && !S_ISDIR(file_stat.st_mode)) {
    return Status::failure("Not a regular file or directory: " + path);
  }

  auto fd = ::open(("/proc/self/fd/" + std::to_string(path_fd)).c_str(),
                   O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0) {
    return Status::failure("Failed to open file: " + path);
  }

  auto fd_guard = scope_guard::create([fd]() { ::close(fd); });

  int raw_flags = 0;
  if (::ioctl(fd, FS_IOC_GETFLAGS, &raw_flags) != 0) {
    return Status::failure("Filesystem does not support FS_IOC_GETFLAGS for: " +
                           path);
  }

  flags = static_cast<std::uint32_t>(raw_flags);
  return Status::success();
}

Status describeFilesystemFileFlags(std::string& output, std::uint32_t flags) {
  output.clear();

  static const auto flag_mask = getFsFlagMask();

  std::vector<std::string> label_list;

  for (const auto& p : kFsFlagMap) {
    const auto& bit = p.first;
    const auto& label = p.second;

    if ((flags & bit) != 0U) {
      label_list.push_back(label);
    }
  }

  // Get the bits that are not documented and show them as a hex number
  auto undocumented_flags = flags & (~flag_mask);
  if (undocumented_flags != 0U) {
    std::stringstream buffer;
    buffer << "0x" << std::setw(8) << std::setfill('0') << std::hex
           << undocumented_flags;

    label_list.push_back(buffer.str());
  }

  output = boost::algorithm::join(label_list, ", ");

  if (undocumented_flags != 0U) {
    return Status::failure("undocumented flags present");
  }

  return Status::success();
}
} // namespace osquery
