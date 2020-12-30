/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/optional.hpp>
#include <unordered_map>

#include <osquery/core/core.h>
#include <osquery/filesystem/filesystem.h>

namespace osquery {
// Information about a single mounted filesystem
struct MountInformation final {
  struct StatFsInfo final {
    // Optimal transfer block size (statfs::f_bsize)
    std::uint32_t block_size{0U};

    // Total data blocks in file system (statfs::f_blocks)
    std::uint32_t block_count{0U};

    // Free blocks in filesystem (statfs::f_bfree)
    std::uint32_t free_block_count{0U};

    // Free blocks available to unprivileged user (statfs::f_bavail)
    std::uint32_t unprivileged_free_block_count{0U};

    // Total file nodes in filesystem (statfs::f_files)
    std::uint32_t inode_count{0U};

    // Free file nodes in filesystem (statfs::f_ffree)
    std::uint32_t free_inode_count{0U};
  };

  // Filesystem type
  std::string type;

  // Device path
  std::string device;

  // Canonicalized device path
  std::string device_alias;

  // Mount path
  std::string path;

  // Mount options
  std::string flags;

  // statfs information; may not be set if the statfs operation
  // has failed
  boost::optional<StatFsInfo> optional_statfs_info;
};

// Information about all mounted filesystems
using MountedFilesystems = std::vector<MountInformation>;

Status getMountedFilesystems(MountedFilesystems& mounted_fs_info);
} // namespace osquery
