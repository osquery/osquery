/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/filesystem/linux/mounts.h>
#include <osquery/logger/logger.h>

namespace osquery {
namespace tables {
QueryData genMounts(QueryContext& context) {
  MountedFilesystems mounted_fs{};
  auto status = getMountedFilesystems(mounted_fs);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to list the system mounts: " << status.getMessage();
    return {};
  }

  QueryData results;

  for (const auto& mount_info : mounted_fs) {
    Row r = {};

    r["type"] = mount_info.type;
    r["device"] = mount_info.device;
    r["device_alias"] = mount_info.device_alias;
    r["path"] = mount_info.path;
    r["flags"] = mount_info.flags;

    // optional::has_value is not present in Boost 1.66 (which is
    // what we have when compiling with BUCK)
    if (mount_info.optional_statfs_info != boost::none) {
      const auto& statfs_info = mount_info.optional_statfs_info.value();

      r["blocks_size"] = BIGINT(statfs_info.block_size);
      r["blocks"] = BIGINT(statfs_info.block_count);
      r["blocks_free"] = BIGINT(statfs_info.free_block_count);

      r["blocks_available"] = BIGINT(statfs_info.unprivileged_free_block_count);

      r["inodes"] = BIGINT(statfs_info.inode_count);
      r["inodes_free"] = BIGINT(statfs_info.free_inode_count);

    } else {
      r["blocks_size"] = BIGINT(0);
      r["blocks"] = BIGINT(0);
      r["blocks_free"] = BIGINT(0);
      r["blocks_available"] = BIGINT(0);
      r["inodes"] = BIGINT(0);
      r["inodes_free"] = BIGINT(0);
    }

    results.push_back(std::move(r));
  }

  return results;
}
} // namespace tables
} // namespace osquery
