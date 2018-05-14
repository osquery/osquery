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

#include <osquery/tables.h>

#define DECLARE_TABLE_IMPLEMENTATION_cups_jobs
#include <generated/tables/tbl_cups_jobs_defs.hpp>

namespace osquery {
namespace tables {

class CupsJobs {
 public:
  // The array given to us by the CUPS API
  cups_job_t* job_list;
  // How long the array is
  int num_jobs;

  CupsJobs() : job_list(nullptr), num_jobs(0) {
    num_jobs = cupsGetJobs(&job_list, nullptr, 0, CUPS_WHICHJOBS_ALL);
  }

  ~CupsJobs() {
    cupsFreeJobs(num_jobs, job_list);
  }

  cups_job_t* begin() {
    return job_list;
  }

  cups_job_t* end() {
    return &job_list[num_jobs];
  }
};

QueryData genCupsJobs(QueryContext& request) {
  QueryData results;
  CupsJobs jobs;

  for (const auto& job : jobs) {
    Row r;
    r["title"] = SQL_TEXT(job.title);
    r["destination"] = SQL_TEXT(job.dest);
    r["user"] = SQL_TEXT(job.user);
    r["format"] = SQL_TEXT(job.format);
    r["size"] = INTEGER(job.size);
    r["completed_time"] = INTEGER(job.completed_time);
    r["processing_time"] = INTEGER(job.processing_time);
    r["creation_time"] = INTEGER(job.creation_time);
    results.push_back(r);
  }
  return results;
}

} // namespace tables
} // namespace osquery
