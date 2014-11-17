// Copyright 2014-present Mike Goffin. All Rights Reserved.

#include <stdio.h>
#include <sys/mount.h>

#include "osquery/database.h"

namespace osquery {
namespace tables {

QueryData genMounts() {
  Row r;
  QueryData results;

  struct statfs *mnt;
  int mnts = 0;
  int i;

  mnts = getmntinfo(&mnt, MNT_WAIT);
  if (mnts == 0) {
    return results;
  }
  for (i = 0; i < mnts; i++) {
    r["name"] = TEXT(mnt[i].f_mntonname);
    r["device"] = TEXT(mnt[i].f_mntfromname);
    r["fstype"] = TEXT(mnt[i].f_fstypename);
    r["size"] = INTEGER(mnt[i].f_bsize);
    r["blocks"] = INTEGER(mnt[i].f_blocks);
    r["free"] = INTEGER(mnt[i].f_bfree);
    r["available"] = INTEGER(mnt[i].f_bavail);
    r["files"] = INTEGER(mnt[i].f_files);
    r["ffree"] = INTEGER(mnt[i].f_ffree);
    r["owner"] = INTEGER(mnt[i].f_owner);
    results.push_back(r);
  }
  return results;
}
}
}
