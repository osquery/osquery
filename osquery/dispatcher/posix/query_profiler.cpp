/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#ifdef __linux__
// Needed for linux specific RUSAGE_THREAD, before including anything else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include <cerrno>
#include <cstring>
#include <cstdint>

#include <sys/resource.h>
#include <sys/time.h>

#include <boost/format.hpp>
#include <boost/io/detail/quoted_manip.hpp>

#include <osquery/dispatcher/query_profiler.h>
#include <osquery/logger.h>
#include <osquery/numeric_monitoring.h>

namespace osquery {
namespace {

int getRusageWho() {
  return
#ifdef __linux__
      RUSAGE_THREAD; // Linux supports more granular profiling
#else
      RUSAGE_SELF;
#endif
}

void recordRusageStatDifference(int64_t start_stat,
                                int64_t end_stat,
                                const std::string& stat_name) {
  if (end_stat == 0) {
    TLOG << "rusage field " << boost::io::quoted(stat_name)
         << " is not supported";
  } else if (start_stat <= end_stat) {
    monitoring::record(
        stat_name, end_stat - start_stat, monitoring::PreAggregationType::P50);
  } else {
    LOG(WARNING) << "Possible overflow detected in rusage field: "
                 << boost::io::quoted(stat_name);
  }
}

void recordRusageStatDifference(const struct timeval& start_stat,
                                const struct timeval& end_stat,
                                const std::string& stat_name) {
  recordRusageStatDifference(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::seconds(start_stat.tv_sec) +
          std::chrono::microseconds(start_stat.tv_usec))
          .count(),
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::seconds(end_stat.tv_sec) +
          std::chrono::microseconds(end_stat.tv_usec))
          .count(),
      stat_name);
}

void recordRusageStatDifference(const struct rusage& start_stats,
                                const struct rusage& end_stats,
                                const std::string& monitoring_path_prefix) {
  recordRusageStatDifference(
      0, end_stats.ru_maxrss, monitoring_path_prefix + ".rss.max.kb");

  recordRusageStatDifference(start_stats.ru_maxrss,
                             end_stats.ru_maxrss,
                             monitoring_path_prefix + ".rss.increase.kb");

  recordRusageStatDifference(start_stats.ru_inblock,
                             end_stats.ru_inblock,
                             monitoring_path_prefix + ".input.load");

  recordRusageStatDifference(start_stats.ru_oublock,
                             end_stats.ru_oublock,
                             monitoring_path_prefix + ".output.load");

  recordRusageStatDifference(start_stats.ru_utime,
                             end_stats.ru_utime,
                             monitoring_path_prefix + ".time.user.milis");

  recordRusageStatDifference(start_stats.ru_stime,
                             end_stats.ru_stime,
                             monitoring_path_prefix + ".time.system.milis");
}

enum class RusageError { FatalError = 1 };
Expected<struct rusage, RusageError> callRusage() {
  struct rusage stats;
  const int who = getRusageWho();
  auto rusage_status = getrusage(who, &stats);
  if (rusage_status != -1) {
    return stats;
  } else {
    return createError(RusageError::FatalError, "")
           << "Linux query profiling failed. error code: " << rusage_status
           << " message: " << boost::io::quoted(strerror(errno));
  }
}

void launchQueryWithPosixProfiling(const std::string& name,
                                   std::function<Status()> launchQuery) {
  const auto start_time_point = std::chrono::steady_clock::now();
  auto rusage_start = callRusage();

  if (!rusage_start) {
    LOG(ERROR) << "rusage_start error: "
               << rusage_start.getError().getFullMessageRecursive();
  }

  const auto status = launchQuery();
  const auto monitoring_path_prefix =
      (boost::format("scheduler.executing_query.%s.%s") % name %
       (status.ok() ? "success" : "failure"))
          .str();

  if (rusage_start) {
    const auto rusage_end = callRusage();

    if (rusage_end) {
      recordRusageStatDifference(
          *rusage_start, *rusage_end, monitoring_path_prefix);
    } else {
      LOG(ERROR) << "rusage_end error: "
                 << rusage_end.getError().getFullMessageRecursive();
    }
  }

  const auto query_duration =
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now() - start_time_point);
  if (Killswitch::get().isExecutingQueryMonitorEnabled()) {
    monitoring::record(monitoring_path_prefix + ".time.real.milis",
                       query_duration.count(),
                       monitoring::PreAggregationType::Min);
  }
}
} // namespace
void launchQueryWithProfiling(const std::string& name,
                              std::function<Status()> launchQuery) {
  if (Killswitch::get().isPosixProfilingEnabled()) {
    launchQueryWithPosixProfiling(name, launchQuery);
  } else {
    launchQuery(); // Just execute the query
  }
}

} // namespace osquery
