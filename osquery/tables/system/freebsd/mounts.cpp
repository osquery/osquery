/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sys/mount.h>
#include <sys/param.h>
#include <sys/ucred.h>

#include <string>
#include <vector>

#include <osquery/core/tables.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {
namespace tables {

static std::string mntFlagsToString(uint64_t f) {
  struct {
    uint64_t v;
    const char* n;
  } map[] = {
      {MNT_RDONLY, "ro"},
      {MNT_SYNCHRONOUS, "sync"},
      {MNT_NOEXEC, "noexec"},
      {MNT_NOSUID, "nosuid"},
      {MNT_UNION, "union"},
      {MNT_ASYNC, "async"},
      {MNT_SUIDDIR, "suiddir"},
      {MNT_SOFTDEP, "soft-updates"},
      {MNT_NOSYMFOLLOW, "nosymfollow"},
      {MNT_NOATIME, "noatime"},
      {MNT_MULTILABEL, "multilabel"},
      {MNT_ACLS, "acls"},
      {MNT_NFS4ACLS, "nfsv4acls"},
      {MNT_LOCAL, "local"},
      {MNT_QUOTA, "with-quotas"},
      {MNT_ROOTFS, "root"},
      {MNT_AUTOMOUNTED, "automounted"},
  };
  std::string out;
  for (auto& e : map) {
    if (f & e.v) {
      if (!out.empty())
        out += ",";
      out += e.n;
    }
  }
  return out;
}

QueryData genMounts(QueryContext& context) {
  QueryData results;
  struct statfs* mntbuf = nullptr;
  int n = getmntinfo(&mntbuf, MNT_NOWAIT);
  if (n <= 0 || mntbuf == nullptr) {
    return results;
  }
  for (int i = 0; i < n; i++) {
    Row r;
    r["device"] = mntbuf[i].f_mntfromname;
    r["device_alias"] = mntbuf[i].f_mntfromname;
    r["path"] = mntbuf[i].f_mntonname;
    r["type"] = mntbuf[i].f_fstypename;
    r["blocks_size"] = BIGINT((uint64_t)mntbuf[i].f_bsize);
    r["blocks"] = BIGINT((uint64_t)mntbuf[i].f_blocks);
    r["blocks_free"] = BIGINT((uint64_t)mntbuf[i].f_bfree);
    r["blocks_available"] = BIGINT((int64_t)mntbuf[i].f_bavail);
    r["inodes"] = BIGINT((uint64_t)mntbuf[i].f_files);
    r["inodes_free"] = BIGINT((int64_t)mntbuf[i].f_ffree);
    r["flags"] = mntFlagsToString(mntbuf[i].f_flags);
    results.push_back(r);
  }
  return results;
}

} // namespace tables
} // namespace osquery
