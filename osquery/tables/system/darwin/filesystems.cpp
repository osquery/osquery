/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "filesystems.h"

#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>

#include <glog/logging.h>

#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData parseStatfs(const struct statfs fs_infos[], int fs_count) {
  Row r;
  QueryData results;

  for (int i = 0; i < fs_count; ++i) {
    const struct statfs& fs_info = fs_infos[i];
    r["name"] = fs_info.f_mntfromname;
    r["path"] = fs_info.f_mntonname;
    r["type"] = fs_info.f_fstypename;
    results.push_back(r);
  }

  return results;
}

QueryData genFilesystems(QueryContext& context) {
    // First get count of filesystems
    int fs_count = getfsstat(NULL, 0, 0);
    if (fs_count == -1) {
      LOG(ERROR) << "Error retrieving filesystems count from getfsstat";
      return {};
    }

    size_t fs_infos_size = fs_count * sizeof(struct statfs);
    std::unique_ptr<struct statfs[]> fs_infos(new struct statfs[fs_infos_size]);
    if (fs_infos == NULL) {
      LOG(ERROR) << "Error allocating fs_info structs";
      return {};
    }

    // Now fill fs_infos with the full info for each fs (fs_count may have
    // changed in the meantime, so save the value returned again)
    fs_count = getfsstat(fs_infos.get(), fs_infos_size, 0);
    if (fs_count == -1) {
      LOG(ERROR) << "Error retrieving getfsstat info";
      return {};
    }

    return parseStatfs(fs_infos.get(), fs_count);
  }
}
}
