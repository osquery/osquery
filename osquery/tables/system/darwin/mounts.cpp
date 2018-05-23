/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <stdio.h>
#include <sys/mount.h>

#include "osquery/core/utils.h"
#include <osquery/tables.h>

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

    char* real_path = canonicalize_file_name(mnt[i].f_mntfromname);
    if (real_path) {
      r["device_alias"] = std::string(real_path);
      free(real_path);
    } else {
      r["device_alias"] = mnt[i].f_mntfromname;
    }

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
