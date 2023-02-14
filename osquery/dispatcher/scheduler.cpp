/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "osquery/dispatcher/scheduler.h"

#include <algorithm>
#include <ctime>

#include <boost/format.hpp>
#include <boost/io/quoted.hpp>

#include <osquery/carver/carver.h>
#include <osquery/config/config.h>
#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/core/query.h>
#include <osquery/core/shutdown.h>
#include <osquery/database/database.h>
#include <osquery/logger/data_logger.h>
#include <osquery/numeric_monitoring/numeric_monitoring.h>
#include <osquery/process/process.h>
#include <osquery/profiler/code_profiler.h>
#include <osquery/sql/sqlite_util.h>
#include <osquery/utils/expected/expected.h>
#include <osquery/utils/system/time.h>
#include <osquery/worker/system/memory.h>
#include <plugins/config/parsers/decorators.h>

namespace osquery {

FLAG(uint64,
     schedule_timeout,
     0,
     "Limit the schedule to a duration in seconds, 0 for no limit");

FLAG(uint64, schedule_max_drift, 60, "Max time drift in seconds");

FLAG(uint64,
     schedule_reload,
     3600,
     "Interval in seconds to reload database arenas");

FLAG(uint64, schedule_epoch, 0, "Epoch for scheduled queries");

FLAG(bool,
     schedule_lognames,
     false,
     "Log the running scheduled query name at INFO level");

HIDDEN_FLAG(bool,
            schedule_reload_sql,
            false,
            "Reload the SQL implementation during schedule reload");

/// Used to bypass (optimize-out) the set-differential of query results.
DECLARE_bool(events_optimize);
DECLARE_bool(enable_numeric_monitoring);
DECLARE_bool(verbose);

SQLInternal monitor(const std::string& name, const ScheduledQuery& query) {
  if (FLAGS_enable_numeric_monitoring) {
    CodeProfiler profiler(
        {(boost::format("scheduler.pack.%s") % query.pack_name).str(),
         (boost::format("scheduler.global.query.%s.%s") % query.pack_name %
          query.name)
             .str(),
         (boost::format("scheduler.assigned.query.%s.%s.%s") % query.oncall %
          query.pack_name % query.name)
             .str(),
         (boost::format("scheduler.owners.%s") % query.oncall).str(),
         (boost::format("scheduler.query.%s.%s.%s") %
          monitoring::hostIdentifierKeys().scheme % query.pack_name %
          query.name)
             .str()});
    return SQLInternal(query.query, true);
  } else {
    // Snapshot the performance and times for the worker before running.
    auto pid = std::to_string(PlatformProcess::getCurrentPid());
    auto r0 = SQL::selectFrom({"resident_size", "user_time", "system_time"},
                              "processes",
                              "pid",
                              EQUALS,
                              pid);

    using namespace std::chrono;
    auto t0 = steady_clock::now();
    Config::get().recordQueryStart(name);
    SQLInternal sql(query.query, true);

    // Snapshot the performance after, and compare.
    auto t1 = steady_clock::now();
    auto r1 = SQL::selectFrom({"resident_size", "user_time", "system_time"},
                              "processes",
                              "pid",
                              EQUALS,
                              pid);
    if (r0.size() > 0 && r1.size() > 0) {
      // Always called while processes table is working.
      uint64_t size = sql.getSize();
      Config::get().recordQueryPerformance(
          name,
          duration_cast<milliseconds>(t1 - t0).count(),
          size,
          r0[0],
          r1[0]);
    }
    return sql;
  }
}

Status launchQuery(const std::string& name, const ScheduledQuery& query) {
  // Execute the scheduled query and create a named query object.
  if (FLAGS_verbose) {
    VLOG(1) << "Executing scheduled query " << name << ": " << query.query;
  } else if (FLAGS_schedule_lognames) {
    LOG(INFO) << "Executing scheduled query " << name;
  }
  runDecorators(DECORATE_ALWAYS);

  auto sql = monitor(name, query);
  if (!sql.getStatus().ok()) {
    LOG(ERROR) << "Error executing scheduled query " << name << ": "
               << sql.getStatus().toString();
    return Status::failure("Error executing scheduled query");
  }

  // Fill in a host identifier fields based on configuration or availability.
  std::string ident = getHostIdentifier();

  // A query log item contains an optional set of differential results or
  // a copy of the most-recent execution alongside some query metadata.
  QueryLogItem item;
  item.name = name;
  item.identifier = ident;
  item.time = osquery::getUnixTime();
  item.epoch = FLAGS_schedule_epoch;
  item.calendar_time = osquery::getAsciiTime();
  item.isSnapshot = false;
  getDecorations(item.decorations);

  if (query.isSnapshotQuery()) {
    // This is a snapshot query, emit results without a differential or state.
    item.isSnapshot = true;
    item.snapshot_results = std::move(sql.rowsTyped());
    auto status = logSnapshotQuery(item);
    if (!status.ok()) {
      // If log directory is not available, then the daemon shouldn't continue.
      std::string message = "Error logging the results of query: " + name +
                            ": " + status.toString();
      requestShutdown(EXIT_CATASTROPHIC, message);
    }
    return status;
  }

  // Create a database-backed set of query results.
  auto dbQuery = Query(name, query);
  // Comparisons and stores must include escaped data.
  sql.escapeResults();
  Status status;
  DiffResults& diff_results = item.results;
  // Add this execution's set of results to the database-tracked named query.
  // We can then ask for a differential from the last time this named query
  // was executed by exact matching each row.
  if (!FLAGS_events_optimize || !sql.eventBased()) {
    status = dbQuery.addNewResults(
        std::move(sql.rowsTyped()), item.epoch, item.counter, diff_results);
  } else {
    status = dbQuery.addNewEvents(
        std::move(sql.rowsTyped()), item.epoch, item.counter, diff_results);
  }

  if (!status.ok()) {
    std::string message = "Error adding new results to database for query " +
                          name + ": " + status.what();
    // If the database is not available then the daemon cannot continue.
    requestShutdown(EXIT_CATASTROPHIC, message);
  }

  if (!query.reportRemovedRows()) {
    diff_results.removed.clear();
  }

  if (diff_results.hasNoResults() && item.counter != 0) {
    // No diff results or events to emit, return unless this is a
    // periodic snapshot (counter=0) which can emit an empty result.
    return status;
  }

  VLOG(1) << "Found results for query: " << name;

  status = logQueryLogItem(item);
  if (!status.ok()) {
    // If log directory is not available, then the daemon shouldn't continue.
    std::string message = "Error logging the results of query: " + name + ": " +
                          status.toString();
    requestShutdown(EXIT_CATASTROPHIC, message);
  }
  return status;
}

void SchedulerRunner::calculateTimeDriftAndMaybePause(
    std::chrono::milliseconds loop_step_duration) {
  if (loop_step_duration + time_drift_ < interval_) {
    pause(interval_ - loop_step_duration - time_drift_);
    time_drift_ = std::chrono::milliseconds::zero();
  } else {
    time_drift_ += loop_step_duration - interval_;
    if (time_drift_ > max_time_drift_) {
      // giving up
      time_drift_ = std::chrono::milliseconds::zero();
    }
  }
}

void SchedulerRunner::maybeRunDecorators(uint64_t time_step) {
  // Configuration decorators run on 60 second intervals only.
  if ((time_step % 60) == 0) {
    runDecorators(DECORATE_INTERVAL, time_step);
  }
}

void SchedulerRunner::maybeScheduleCarves(uint64_t time_step) {
  if ((time_step % 60) == 0) {
    scheduleCarves();
  }
}

void SchedulerRunner::maybeReloadSchedule(uint64_t time_step) {
  if (FLAGS_schedule_reload > 0 && (time_step % FLAGS_schedule_reload) == 0) {
    /* Before resetting the database we want to ensure that there's no pending
       log relay thread started by the scheduler thread in a previous loop,
       to avoid deadlocks.
       This is because resetDatabase logs and also holds an exclusive lock
       to the database, so when a log relay thread started via relayStatusLog
       is pending, log calls done on the same thread that started it
       (in this case the scheduler thread), will wait until the log relaying
       thread finishes serializing the logs to the database; but this can't
       happen due to the exclusive lock. */
    waitLogRelay();

    if (FLAGS_schedule_reload_sql) {
      SQLiteDBManager::resetPrimary();
    }
    resetDatabase();
  }
}

void SchedulerRunner::maybeFlushLogs(uint64_t time_step) {
  /* In daemon mode we start a log relay thread to flush the logs from the
     BufferedLogSink to the database.
     The thread is started from the scheduler thread,
     since if we did it in the send() function of BufferedLogSink,
     inline to the log call itself, we would cause deadlocks
     if there's recursive logging caused by the logger plugins.
     We do the flush itself also in a new thread so we don't slow down
     the scheduler thread too much */
  if ((time_step % 3) == 0) {
    relayStatusLogs(LoggerRelayMode::Async);
  }
}

void SchedulerRunner::start() {
  // Start the counter at the second.
  auto i = osquery::getUnixTime();
  // Timeout is the number of seconds from starting.
  auto end = (timeout_ == 0) ? 0 : timeout_ + i;

  for (; (end == 0) || (i <= end); ++i) {
    auto start_time_point = std::chrono::steady_clock::now();
    Config::get().scheduledQueries(([&i](const std::string& name,
                                         const ScheduledQuery& query) {
      if (query.splayed_interval > 0 && i % query.splayed_interval == 0) {
        TablePlugin::kCacheInterval = query.splayed_interval;
        TablePlugin::kCacheStep = i;
        const auto status = launchQuery(name, query);
        monitoring::record((boost::format("scheduler.query.%s.%s.status.%s") %
                            query.pack_name % query.name %
                            (status.ok() ? "success" : "failure"))
                               .str(),
                           1,
                           monitoring::PreAggregationType::Sum,
                           true);

#ifdef OSQUERY_LINUX
        // Attempt to release some unused memory kept by malloc internal caching
        releaseRetainedMemory();
#endif
      }
    }));

    maybeRunDecorators(i);
    maybeReloadSchedule(i);
    maybeFlushLogs(i);
    maybeScheduleCarves(i);

    auto loop_step_duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time_point);
    calculateTimeDriftAndMaybePause(loop_step_duration);
    if (interrupted()) {
      break;
    }
  }

  /* Wait for the thread relaying/flushing the logs,
     to prevent race conditions on shutdown */
  waitLogRelay();

  // Scheduler ended.
  if (!interrupted() && request_shutdown_on_expiration) {
    LOG(INFO) << "The scheduler ended after " << timeout_ << " seconds";
    requestShutdown();
  }
}

std::chrono::milliseconds SchedulerRunner::getCurrentTimeDrift() const
    noexcept {
  return time_drift_;
}

void startScheduler() {
  startScheduler(static_cast<unsigned long int>(FLAGS_schedule_timeout), 1);
}

void startScheduler(unsigned long int timeout, size_t interval) {
  Dispatcher::addService(std::make_shared<SchedulerRunner>(
      timeout, interval, std::chrono::seconds{FLAGS_schedule_max_drift}));
}
} // namespace osquery
