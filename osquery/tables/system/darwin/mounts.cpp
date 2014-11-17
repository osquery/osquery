// Copyright 2014-present Mike Goffin. All Rights Reserved.

#include <stdio.h>
#include <sys/mount.h>

#include <boost/lexical_cast.hpp>

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
  if(mnts == 0)
  {
    return results;
  }
  for(i = 0; i < mnts; i++)
  {
      r["Name"] = TEXT(mnt[i].f_mntonname);
      r["Device"] = TEXT(mnt[i].f_mntfromname);
      r["FSType"] = TEXT(mnt[i].f_fstypename);
      r["Size"] = INTEGER(mnt[i].f_bsize);
      r["Blocks"] = INTEGER(mnt[i].f_blocks);
      r["Free"] = INTEGER(mnt[i].f_bfree);
      r["Available"] = INTEGER(mnt[i].f_bavail);
      r["Files"] = INTEGER(mnt[i].f_files);
      r["FFree"] = INTEGER(mnt[i].f_ffree);
      r["Owner"] = INTEGER(mnt[i].f_owner);
      results.push_back(r);
  }
  return results;
}
}
}
