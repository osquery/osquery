/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
 
#include <ctime>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/dispatcher/scheduler.h"

namespace osquery {

FLAG(string,
     host_identifier,
     "hostname",
     "Field used to identify the host running osquery (hostname, uuid)");

FLAG(bool, disable_monitor, false, "Disable the schedule monitor");

CLI_FLAG(uint64, schedule_timeout, 0, "Limit the schedule, 0 for no limit")

Status getHostIdentifier(std::string& ident) {
  std::shared_ptr<DBHandle> db;
  try {
    db = DBHandle::getInstance();
  } catch (const std::runtime_error& e) {
    return Status(1, e.what());
  }

  if (FLAGS_host_identifier != "uuid") {
    // use the hostname as the default machine identifier
    ident = osquery::getHostname();
    return Status(0, "OK");
  }

  std::vector<std::string> results;
  auto status = db->Scan(kConfigurations, results);

  if (!status.ok()) {
    VLOG(1) << "Could not access database; using hostname as host identifier";
    ident = osquery::getHostname();
    return Status(0, "OK");
  }

  if (std::find(results.begin(), results.end(), "hostIdentifier") !=
      results.end()) {
    status = db->Get(kConfigurations, "hostIdentifier", ident);
    if (!status.ok()) {
      VLOG(1) << "Could not access database; using hostname as host identifier";
      ident = osquery::getHostname();
    }
    return status;
  }

  // There was no uuid stored in the database, generate one and store it.
  ident = osquery::generateHostUuid();
  VLOG(1) << "Using uuid " << ident << " as host identifier";
  return db->Put(kConfigurations, "hostIdentifier", ident);
}

inline SQL monitor(const std::string& name, const ScheduledQuery& query) {
  // Snapshot the performance and times for the worker before running.
  auto pid = std::to_string(getpid());
  auto r0 = SQL::selectAllFrom("processes", "pid", tables::EQUALS, pid);
  auto t0 = time(nullptr);
  auto sql = SQL(query.query);
  // Snapshot the performance after, and compare.
  auto t1 = time(nullptr);
  auto r1 = SQL::selectAllFrom("processes", "pid", tables::EQUALS, pid);
  if (r0.size() > 0 && r1.size() > 0) {
    size_t size = 0;
    for (const auto& row : sql.rows()) {
      for (const auto& column : row) {
        size += column.first.size();
        size += column.second.size();
      }
    }
    Config::recordQueryPerformance(name, t1 - t0, size, r0[0], r1[0]);
  }
  return sql;
}

void launchQuery(const std::string& name, const ScheduledQuery& query) {
  // Execute the scheduled query and create a named query object.
  VLOG(1) << "Executing query: " << query.query;
  auto sql = (!FLAGS_disable_monitor) ? monitor(name, query) : SQL(query.query);

  if (!sql.ok()) {
    LOG(ERROR) << "Error executing query (" << query.query
               << "): " << sql.getMessageString();
    return;
  }

  // Fill in a host identifier fields based on configuration or availability.
  std::string ident;
  auto status = getHostIdentifier(ident);
  if (!status.ok() || ident.empty()) {
    ident = "<unknown>";
  }

  // A query log item contains an optional set of differential results or
  // a copy of the most-recent execution alongside some query metadata.
  QueryLogItem item;
  item.name = name;
  item.identifier = ident;
  item.time = osquery::getUnixTime();
  item.calendar_time = osquery::getAsciiTime();

  if (query.options.count("snapshot") && query.options.at("snapshot")) {
    // This is a snapshot query, emit results with a differential or state.
    item.snapshot_results = std::move(sql.rows());
    logSnapshotQuery(item);
    return;
  }

  // Create a database-backed set of query results.
  auto dbQuery = Query(name, query);
  DiffResults diff_results;
  // Add this execution's set of results to the database-tracked named query.
  // We can then ask for a differential from the last time this named query
  // was executed by exact matching each row.
  status = dbQuery.addNewResults(sql.rows(), diff_results);
  if (!status.ok()) {
    LOG(ERROR) << "Error adding new results to database: " << status.what();
    return;
  }

  if (diff_results.added.size() == 0 && diff_results.removed.size() == 0) {
    // No diff results or events to emit.
    return;
  }

  VLOG(1) << "Found results for query (" << name << ") for host: " << ident;
  item.results = diff_results;
  status = logQueryLogItem(item);
  if (!status.ok()) {
    LOG(ERROR) << "Error logging the results of query (" << query.query
               << "): " << status.toString();
  }
}

void SchedulerRunner::enter() {
  time_t t = time(0);
  struct tm* local = localtime(&t);
  unsigned long int i = local->tm_sec;
  for (; (timeout_ == 0) || (i <= timeout_); ++i) {
    {
      ConfigDataInstance config;
      for (const auto& query : config.schedule()) {
        if (i % query.second.splayed_interval == 0) {
          launchQuery(query.first, query.second);
        }
      }
    }
    // Put the thread into an interruptible sleep without a config instance.
    osquery::interruptableSleep(interval_ * 1000);
  }
}

Status startScheduler() {
  if (startScheduler(FLAGS_schedule_timeout, 1).ok()) {
    Dispatcher::joinServices();
    return Status(0, "OK");
  }
  return Status(1, "Could not start scheduler");
}

Status startScheduler(unsigned long int timeout, size_t interval) {
  Dispatcher::getInstance().addService(
      std::make_shared<SchedulerRunner>(timeout, interval));
  return Status(0, "OK");
}
}
