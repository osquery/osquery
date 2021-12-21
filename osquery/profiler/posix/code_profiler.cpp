/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#ifdef __linux__
// Needed for linux specific RUSAGE_THREAD, before including anything else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include <cerrno>
#include <cstdint>
#include <cstring>

#include <sys/resource.h>
#include <sys/time.h>

#include <boost/format.hpp>
#include <boost/io/quoted.hpp>

#include <osquery/logger/logger.h>
#include <osquery/numeric_monitoring/numeric_monitoring.h>
#include <osquery/profiler/code_profiler.h>

namespace osquery {
namespace {

void record(const std::vector<std::string>& names,
            const std::string& metricName,
            monitoring::ValueType measurement) {
  for (const std::string& name : names) {
    const std::string entity = name + "." + metricName;
    monitoring::record(
        entity, measurement, monitoring::PreAggregationType::Min, true);

    monitoring::record(
        entity, measurement, monitoring::PreAggregationType::Sum, true);
  }
}

int getRusageWho() {
  return
#ifdef __linux__
      RUSAGE_THREAD; // Linux supports more granular profiling
#else
      RUSAGE_SELF;
#endif
}

enum class RusageError { FatalError = 1 };

static Expected<struct rusage, RusageError> callRusage() {
  struct rusage stats;
  const int who = getRusageWho();
  auto rusage_status = getrusage(who, &stats);
  if (rusage_status != -1) {
    return stats;
  } else {
    return createError(RusageError::FatalError)
           << "Linux query profiling failed. error code: " << rusage_status
           << " message: " << boost::io::quoted(strerror(errno));
  }
}

void recordRusageStatDifference(const std::vector<std::string>& names,
                                const std::string& stat_name,
                                int64_t start_stat,
                                int64_t end_stat) {
  if (end_stat == 0) {
    TLOG << "rusage field " << boost::io::quoted(stat_name)
         << " is not supported";
  } else if (start_stat <= end_stat) {
    record(names, stat_name, end_stat - start_stat);
  } else {
    LOG(WARNING) << "Possible overflow detected in rusage field: "
                 << boost::io::quoted(stat_name);
  }
}

int64_t covertToMilliseconds(const struct timeval& timepoint) {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::seconds(timepoint.tv_sec) +
             std::chrono::microseconds(timepoint.tv_usec))
      .count();
}

void recordRusageStatDifference(const std::vector<std::string>& names,
                                const std::string& stat_name,
                                const struct timeval& start_stat,
                                const struct timeval& end_stat) {
  recordRusageStatDifference(names,
                             stat_name + ".millis",
                             covertToMilliseconds(start_stat),
                             covertToMilliseconds(end_stat));
}

void recordRusageStatDifference(const std::vector<std::string>& names,
                                const struct rusage& start_stats,
                                const struct rusage& end_stats) {
  recordRusageStatDifference(names, "rss.max.kb", 0, end_stats.ru_maxrss);

  recordRusageStatDifference(
      names, "rss.increase.kb", start_stats.ru_maxrss, end_stats.ru_maxrss);

  recordRusageStatDifference(
      names, "input.load", start_stats.ru_inblock, end_stats.ru_inblock);

  recordRusageStatDifference(
      names, "output.load", start_stats.ru_oublock, end_stats.ru_oublock);

  recordRusageStatDifference(
      names, "time.user", start_stats.ru_utime, end_stats.ru_utime);

  recordRusageStatDifference(
      names, "time.system", start_stats.ru_stime, end_stats.ru_stime);

  recordRusageStatDifference(names,
                             "time.total.millis",
                             covertToMilliseconds(start_stats.ru_utime) +
                                 covertToMilliseconds(start_stats.ru_stime),
                             covertToMilliseconds(end_stats.ru_utime) +
                                 covertToMilliseconds(end_stats.ru_stime));
}

} // namespace

class CodeProfiler::CodeProfilerData {
 public:
  CodeProfilerData()
      : rusage_data_(callRusage()),
        wall_time_(std::chrono::steady_clock::now()) {}

  const std::chrono::time_point<std::chrono::steady_clock>& getWallTime() {
    return wall_time_;
  }
  Expected<struct rusage, RusageError> takeRusageData() {
    return std::move(rusage_data_);
  }

 private:
  Expected<struct rusage, RusageError> rusage_data_;
  std::chrono::time_point<std::chrono::steady_clock> wall_time_;
};

CodeProfiler::CodeProfiler(const std::initializer_list<std::string>& names)
    : names_(names), code_profiler_data_(new CodeProfilerData()) {}

CodeProfiler::~CodeProfiler() {
  CodeProfilerData code_profiler_data_end;

  auto rusage_start = code_profiler_data_->takeRusageData();
  if (!rusage_start) {
    LOG(ERROR) << "rusage_start error: "
               << rusage_start.getError().getMessage();
  } else {
    auto rusage_end = code_profiler_data_end.takeRusageData();
    if (!rusage_end) {
      LOG(ERROR) << "rusage_end error: " << rusage_end.getError().getMessage();
    } else {
      recordRusageStatDifference(names_, *rusage_start, *rusage_end);
    }

    const auto query_duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            code_profiler_data_end.getWallTime() -
            code_profiler_data_->getWallTime());
    record(names_, "time.wall.millis", query_duration.count());
  }
}

} // namespace osquery
