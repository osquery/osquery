/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <ctime>

#include <boost/asio/deadline_timer.hpp>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/query.h>
#include <osquery/system.h>

#include "osquery/config/parsers/decorators.h"
#include "osquery/core/process.h"
#include "osquery/dispatcher/io_service.h"
#include "osquery/dispatcher/scheduler.h"
#include "osquery/sql/sqlite_util.h"

namespace osquery {

FLAG(uint64, schedule_timeout, 0, "Limit the schedule, 0 for no limit");

FLAG(uint64,
     schedule_reload,
     300,
     "Interval in seconds to reload database arenas");

FLAG(uint64, schedule_epoch, 0, "Epoch for scheduled queries");

FLAG(uint32,
     query_short_interval,
     600,
     "Query intervals under this value will be classified as short intervals");

HIDDEN_FLAG(bool, enable_monitor, true, "Enable the schedule monitor");

HIDDEN_FLAG(bool,
            schedule_reload_sql,
            false,
            "Reload the SQL implementation during schedule reload");

/// Used to bypass (optimize-out) the set-differential of query results.
DECLARE_bool(events_optimize);

Mutex schedule_monitor_mutex_;

SQLInternal monitor(const std::string& name, const ScheduledQuery& query) {
  WriteLock lock(schedule_monitor_mutex_);
  // Snapshot the performance and times for the worker before running.
  auto pid = std::to_string(PlatformProcess::getCurrentPid());
  auto r0 = SQL::selectAllFrom("processes", "pid", EQUALS, pid);
  auto t0 = getUnixTime();
  Config::get().recordQueryStart(name);
  SQLInternal sql(query.query, true);
  // Snapshot the performance after, and compare.
  auto t1 = getUnixTime();
  auto r1 = SQL::selectAllFrom("processes", "pid", EQUALS, pid);
  if (r0.size() > 0 && r1.size() > 0) {
    // Calculate a size as the expected byte output of results.
    // This does not dedup result differentials and is not aware of snapshots.
    size_t size = 0;
    for (const auto& row : sql.rows()) {
      for (const auto& column : row) {
        size += column.first.size();
        size += column.second.size();
      }
    }
    // Always called while processes table is working.
    Config::get().recordQueryPerformance(name, t1 - t0, size, r0[0], r1[0]);
  }
  return sql;
}

inline void launchQuery(const std::string& name, const ScheduledQuery& query) {
  // Execute the scheduled query and create a named query object.
  VLOG(1) << "Executing scheduled query " << name << ": " << query.query;
  runDecorators(DECORATE_ALWAYS);

  auto sql = monitor(name, query);
  if (!sql.ok()) {
    LOG(ERROR) << "Error executing scheduled query " << name << ": "
               << sql.getMessageString();
    return;
  }

  // Fill in a host identifier fields based on configuration or availability.
  std::string ident = getHostIdentifier();

  // A query log item contains an optional set of differential results or
  // a copy of the most-recent execution alongside some query metadata.
  QueryLogItem item;
  item.name = name;
  item.identifier = ident;
  item.columns = sql.columns();
  item.time = osquery::getUnixTime();
  item.epoch = FLAGS_schedule_epoch;
  item.calendar_time = osquery::getAsciiTime();
  getDecorations(item.decorations);

  if (query.options.count("snapshot") && query.options.at("snapshot")) {
    // This is a snapshot query, emit results with a differential or state.
    item.snapshot_results = std::move(sql.rows());
    logSnapshotQuery(item);
    return;
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
        std::move(sql.rows()), item.epoch, item.counter, diff_results);
    if (!status.ok()) {
      std::string line =
          "Error adding new results to database: " + status.what();
      LOG(ERROR) << line;

      // If the database is not available then the daemon cannot continue.
      Initializer::requestShutdown(EXIT_CATASTROPHIC, line);
    }
  } else {
    diff_results.added = std::move(sql.rows());
  }

  if (query.options.count("removed") && !query.options.at("removed")) {
    diff_results.removed.clear();
  }

  if (diff_results.added.empty() && diff_results.removed.empty()) {
    // No diff results or events to emit.
    return;
  }

  VLOG(1) << "Found results for query: " << name;

  status = logQueryLogItem(item);
  if (!status.ok()) {
    // If log directory is not available, then the daemon shouldn't continue.
    std::string error = "Error logging the results of query: " + name + ": " +
                        status.toString();
    LOG(ERROR) << error;
    Initializer::requestShutdown(EXIT_CATASTROPHIC, error);
  }
}

void SchedulerRunner::scheduleQueries(size_t present_time) {
  Config::get().scheduledQueries(
      ([&present_time](const std::string& name, ScheduledQuery& query) {
        if (query.splayed_interval > 0) {
          if ((query.interval > FLAGS_query_short_interval &&
               (present_time - query.last_runtime) >= query.splayed_interval) ||
              (query.interval <= FLAGS_query_short_interval &&
               (present_time % query.splayed_interval == 0))) {
            if (!*query.is_scheduled) {
              TablePlugin::kCacheInterval = query.splayed_interval;
              TablePlugin::kCacheStep = present_time;
              query.last_runtime = present_time;
              *query.is_scheduled = true;
              IOService::get().post([name, &query]() {
                launchQuery(name, query);
                *query.is_scheduled = false;
              });
            }
          }
        }
      }));
  // Configuration decorators run on 60 second intervals only.
  if ((present_time % 60) == 0) {
    runDecorators(DECORATE_INTERVAL, present_time);
  }
  if (FLAGS_schedule_reload > 0 &&
      (present_time % FLAGS_schedule_reload) == 0) {
    if (FLAGS_schedule_reload_sql) {
      SQLiteDBManager::resetPrimary();
    }
    resetDatabase();
  }

  // GLog is not re-entrant, so logs must be flushed in a dedicated thread.
  if ((present_time % 3) == 0) {
    relayStatusLogs(true);
  }
}

void SchedulerRunner::start() {
  boost::asio::deadline_timer dl_timer{ios_};
  size_t time_is;

  do {
    time_is =
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    ios_.reset();
    dl_timer.expires_at((boost::posix_time::from_time_t(time_is + interval_)));
    dl_timer.async_wait([&](boost::system::error_code const&) {
      this->scheduleQueries(time_is + interval_);
    });
    ios_.run();
  } while (!is_stopped_ &&
           ((timeout_ == 0) || (time_is + interval_) <= timeout_));
}

void SchedulerRunner::stop() {
  is_stopped_ = true;
  ios_.stop();
}

void startScheduler() {
  startScheduler(static_cast<unsigned long int>(FLAGS_schedule_timeout), 1);
}

void startScheduler(unsigned long int timeout, size_t interval) {
  Dispatcher::addService(std::make_shared<SchedulerRunner>(timeout, interval));
}
} // namespace osquery
