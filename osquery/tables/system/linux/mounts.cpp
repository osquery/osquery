// Copyright 2004-present Facebook. All Rights Reserved.

#include <mntent.h>
#include <sys/vfs.h>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData genMounts(QueryContext &context) {
  QueryData results;
  FILE *mounts;
  struct mntent *ent;
  char real_path[PATH_MAX];
  struct statfs st;

  if ((mounts = setmntent("/proc/mounts", "r"))) {
    while ((ent = getmntent(mounts))) {
      Row r;

      r["device"] = std::string(ent->mnt_fsname);
      r["device_alias"] = std::string(
          realpath(ent->mnt_fsname, real_path) ? real_path : ent->mnt_fsname);
      r["path"] = std::string(ent->mnt_dir);
      r["type"] = std::string(ent->mnt_type);
      r["flags"] = std::string(ent->mnt_opts);
      if (!statfs(ent->mnt_dir, &st)) {
        r["blocks_size"] = BIGINT(st.f_bsize);
        r["blocks"] = BIGINT(st.f_blocks);
        r["blocks_free"] = BIGINT(st.f_bfree);
        r["blocks_available"] = BIGINT(st.f_bavail);
        r["inodes"] = BIGINT(st.f_files);
        r["inodes_free"] = BIGINT(st.f_ffree);
      }

      results.push_back(r);
    }
    endmntent(mounts);
  }

  return results;
}
}
}
