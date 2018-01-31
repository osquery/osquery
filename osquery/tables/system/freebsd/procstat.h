/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <sys/queue.h>
#include <sys/user.h>

#include <libprocstat.h>

#include <osquery/tables.h>

namespace osquery {
namespace tables {

/**
 * A helper function to retrieve processes using libprocstat(3). It is the
 * responsibility of the caller to call procstat_freeprocs() and
 * procstat_close() when done.
 *
 * Returns the number of processes in the "procs" list. On failure, returns 0
 * and sets pstat and procs to NULL.
 *
 * Errors are not well exposed in some of the calls in libprocstat(3). This is
 * a bit of a bummer as libkvm(3) is much better in that respect but I would
 * rather use libprocstat(3) as it provides a nicer abstraction.
 */
unsigned int getProcesses(QueryContext& context,
                          struct procstat** pstat,
                          struct kinfo_proc** procs);

/// Helper function to cleanup the libprocstat(3) pointers used.
void procstatCleanup(struct procstat* pstat, struct kinfo_proc* procs);
}
}
