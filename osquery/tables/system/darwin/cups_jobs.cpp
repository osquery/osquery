/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <cups/cups.h>

#include <osquery/system.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

class SafeCupsJobs {
 public:
  cups_job_t* job_list;
  int num_jobs;

  SafeCupsJobs() {
    num_jobs = cupsGetJobs(&job_list, nullptr, 0, CUPS_WHICHJOBS_ALL);
  }

  ~SafeCupsJobs() {
    cupsFreeJobs(num_jobs, job_list);
  }
};

QueryData genCupsJobs(QueryContext& request) {
  QueryData results;
  SafeCupsJobs jobs;

  for (decltype(jobs.num_jobs) i = 0; i < jobs.num_jobs; ++i) {
    Row r;
    r["title"] = SQL_TEXT(jobs.job_list[i].title);
    r["destination"] = SQL_TEXT(jobs.job_list[i].dest);
    r["user"] = SQL_TEXT(jobs.job_list[i].user);
    r["format"] = SQL_TEXT(jobs.job_list[i].format);
    r["size"] = INTEGER(jobs.job_list[i].size);
    r["completed_time"] = INTEGER(jobs.job_list[i].completed_time);
    r["processing_time"] = INTEGER(jobs.job_list[i].processing_time);
    r["creation_time"] = INTEGER(jobs.job_list[i].creation_time);
    results.push_back(r);
  }
  return results;
}

} // namespace tables
} // namespace osquery
