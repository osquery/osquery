/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <sys/queue.h>
#include <sys/user.h>
#include <libprocstat.h>

#include <osquery/tables.h>

namespace osquery {
namespace tables {

unsigned int getProcesses(QueryContext& context,
                          struct procstat** pstat,
                          struct kinfo_proc** procs);

void procstatCleanup(struct procstat* pstat, struct kinfo_proc* procs);

}
}
