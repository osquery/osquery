/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <mntent.h>
#include <sys/vfs.h>

#include <osquery/filesystem/linux/mounts.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/system/filepath.h>

namespace osquery {
namespace {
const std::string kMountsPseudoFile{"/proc/mounts"};

struct MountDataDeleter final {
  void operator()(FILE* ptr) {
    if (ptr == nullptr) {
      return;
    }

    endmntent(ptr);
  }
};

using MountData = std::unique_ptr<FILE, MountDataDeleter>;

Status getMountData(MountData& obj) {
  obj = {};

  auto mount_data = setmntent(kMountsPseudoFile.c_str(), "r");
  if (mount_data == nullptr) {
    return Status::failure("Failed to open the '" + kMountsPseudoFile +
                           "' pseudo file");
  }

  obj.reset(mount_data);
  return Status::success();
}
} // namespace

Status getMountedFilesystems(MountedFilesystems& mounted_fs_info) {
  mounted_fs_info = {};

  MountData mount_data;
  auto status = getMountData(mount_data);
  if (!status.ok()) {
    return status;
  }

  std::vector<char> string_buffer(4096);

  for (;;) {
    mntent ent = {};
    if (getmntent_r(mount_data.get(),
                    &ent,
                    string_buffer.data(),
                    string_buffer.size()) == nullptr) {
      if (errno != ENOENT) {
        LOG(ERROR) << "getmntent_r failed with errno " << std::to_string(errno);
      }

      break;
    }

    MountInformation mount_info = {};
    mount_info.type = ent.mnt_type;
    mount_info.device = ent.mnt_fsname;
    mount_info.device_alias = canonicalize_file_name(ent.mnt_fsname);
    mount_info.path = ent.mnt_dir;
    mount_info.flags = ent.mnt_opts;

    if (mount_info.type == "autofs") {
      VLOG(1) << "Skipping statfs information for autofs mount: "
              << mount_info.path;

    } else {
      struct statfs stats = {};
      if (statfs(mount_info.path.c_str(), &stats) == 0) {
        MountInformation::StatFsInfo statfs_info = {};

        statfs_info.block_size = static_cast<std::uint32_t>(stats.f_bsize);
        statfs_info.block_count = static_cast<std::uint32_t>(stats.f_blocks);

        statfs_info.free_block_count =
            static_cast<std::uint32_t>(stats.f_bfree);

        statfs_info.unprivileged_free_block_count =
            static_cast<std::uint32_t>(stats.f_bavail);

        statfs_info.inode_count = static_cast<std::uint32_t>(stats.f_files);

        statfs_info.free_inode_count =
            static_cast<std::uint32_t>(stats.f_ffree);

        mount_info.optional_statfs_info = std::move(statfs_info);

      } else {
        LOG(ERROR) << "statfs failed with errno " << std::to_string(errno)
                   << " on path " << mount_info.path;
      }
    }

    mounted_fs_info.emplace_back(std::move(mount_info));
  }

  return Status::success();
}
} // namespace osquery
