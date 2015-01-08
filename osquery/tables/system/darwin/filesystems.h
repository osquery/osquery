/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#ifndef OSQUERY_TABLES_FILESYSTEMS_H
#define OSQUERY_TABLES_FILESYSTEMS_H

#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>

#include <osquery/tables.h>

namespace osquery {
namespace tables {

// Parse the statfs structs returned from a call to getfsstat, returning an
// osquery QueryData object representing the useful information.
osquery::QueryData parseStatfs(const struct statfs fs_infos[], int fs_count);

// Generate a row for each filesystem mounted on this machine
osquery::QueryData genFilesystems(QueryContext& context);
}
}

#endif /* OSQUERY_TABLES_FILESYSTEMS_H */
