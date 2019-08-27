/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <stdio.h>
#include <sys/mount.h>

#include <osquery/tables.h>
#include <osquery/utils/system/filepath.h>

namespace osquery {
namespace tables {

QueryData genMounts(QueryContext& context) {
  QueryData results;

  struct statfs* mnt;
  int mnts = 0;
  int i;

  mnts = getmntinfo(&mnt, MNT_WAIT);
  if (mnts == 0) {
    // Failed to get mount information.
    return results;
  }

  for (i = 0; i < mnts; i++) {
    Row r;
    r["path"] = TEXT(mnt[i].f_mntonname);
    r["device"] = TEXT(mnt[i].f_mntfromname);
    r["device_alias"] = canonicalize_file_name(mnt[i].f_mntfromname);
    r["type"] = TEXT(mnt[i].f_fstypename);
    r["flags"] = INTEGER(mnt[i].f_flags);
    r["blocks"] = BIGINT(mnt[i].f_blocks);
    r["blocks_free"] = BIGINT(mnt[i].f_bfree);
    r["blocks_available"] = BIGINT(mnt[i].f_bavail);
    r["blocks_size"] = BIGINT(mnt[i].f_bsize);
    r["inodes"] = BIGINT(mnt[i].f_files);
    r["inodes_free"] = BIGINT(mnt[i].f_ffree);
    r["owner"] = INTEGER(mnt[i].f_owner);
    results.push_back(r);
  }
  return results;
}
} // namespace tables
} // namespace osquery
