/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <mntent.h>
#include <sys/vfs.h>

#include <set>

#include <osquery/core.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/tables.h>
#include <osquery/utils/system/filepath.h>

namespace osquery {
namespace tables {

std::set<std::string> kMountStatBlacklist = {
    "autofs",
};

QueryData genMounts(QueryContext& context) {
  QueryData results;

  FILE* mounts = setmntent("/proc/mounts", "r");
  if (mounts == nullptr) {
    return {};
  }

  struct mntent* ent = nullptr;
  while ((ent = getmntent(mounts))) {
    Row r;

    r["type"] = std::string(ent->mnt_type);
    r["device"] = std::string(ent->mnt_fsname);
    r["device_alias"] = canonicalize_file_name(ent->mnt_fsname);
    r["path"] = std::string(ent->mnt_dir);
    r["flags"] = std::string(ent->mnt_opts);

    // Check type against blacklist before running statfs.
    if (kMountStatBlacklist.find(r["type"]) == kMountStatBlacklist.end()) {
      struct statfs st;
      if (!statfs(ent->mnt_dir, &st)) {
        r["blocks_size"] = BIGINT(st.f_bsize);
        r["blocks"] = BIGINT(st.f_blocks);
        r["blocks_free"] = BIGINT(st.f_bfree);
        r["blocks_available"] = BIGINT(st.f_bavail);
        r["inodes"] = BIGINT(st.f_files);
        r["inodes_free"] = BIGINT(st.f_ffree);
      }
    }

    results.push_back(std::move(r));
  }
  endmntent(mounts);

  return results;
}
} // namespace tables
} // namespace osquery
