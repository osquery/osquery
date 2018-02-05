/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <mntent.h>
#include <sys/vfs.h>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/tables.h>

#define DECLARE_TABLE_IMPLEMENTATION_mounts
#include <generated/tables/tbl_mounts_defs.hpp>

namespace osquery {
namespace tables {

QueryData genMounts(QueryContext &context) {
  QueryData results;

  FILE *mounts = setmntent("/proc/mounts", "r");
  if (mounts == nullptr) {
    return {};
  }

  char real_path[PATH_MAX + 1] = {0};
  struct mntent *ent = nullptr;
  while ((ent = getmntent(mounts))) {
    Row r;

    r["device"] = std::string(ent->mnt_fsname);
    r["device_alias"] = std::string(
        realpath(ent->mnt_fsname, real_path) ? real_path : ent->mnt_fsname);
    r["path"] = std::string(ent->mnt_dir);
    r["type"] = std::string(ent->mnt_type);
    r["flags"] = std::string(ent->mnt_opts);

    struct statfs st;
    if (!statfs(ent->mnt_dir, &st)) {
      r["blocks_size"] = BIGINT(st.f_bsize);
      r["blocks"] = BIGINT(st.f_blocks);
      r["blocks_free"] = BIGINT(st.f_bfree);
      r["blocks_available"] = BIGINT(st.f_bavail);
      r["inodes"] = BIGINT(st.f_files);
      r["inodes_free"] = BIGINT(st.f_ffree);
    }

    results.push_back(std::move(r));
  }
  endmntent(mounts);

  return results;
}
}
}
