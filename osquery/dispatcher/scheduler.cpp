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
    VLOG(1) << "Could not access database, using hostname as the host "
               "identifier";
    ident = osquery::getHostname();
    return Status(0, "OK");
  }

  if (std::find(results.begin(), results.end(), "hostIdentifier") !=
      results.end()) {
    status = db->Get(kConfigurations, "hostIdentifier", ident);
    if (!status.ok()) {
      VLOG(1) << "Could not access database, using hostname as the host "
                 "identifier";
      ident = osquery::getHostname();
    }
    return status;
  }

  // There was no uuid stored in the database, generate one and store it.
  ident = osquery::generateHostUuid();
  VLOG(1) << "Using uuid " << ident << " to identify this host";
  return db->Put(kConfigurations, "hostIdentifier", ident);
}

void launchQuery(const std::string& name, const ScheduledQuery& query) {
  LOG(INFO) << "Executing query: " << query.query;
  int unix_time = std::time(0);
  auto sql = SQL(query.query);
  if (!sql.ok()) {
    LOG(ERROR) << "Error executing query (" << query.query
               << "): " << sql.getMessageString();
    return;
  }

  auto dbQuery = Query(name, query);
  DiffResults diff_results;
  auto status = dbQuery.addNewResults(sql.rows(), diff_results, unix_time);
  if (!status.ok()) {
    LOG(ERROR) << "Error adding new results to database: " << status.what();
    return;
  }

  if (diff_results.added.size() == 0 && diff_results.removed.size() == 0) {
    // No diff results or events to emit.
    return;
  }

  ScheduledQueryLogItem item;
  item.diffResults = diff_results;
  item.name = name;

  std::string ident;
  status = getHostIdentifier(ident);
  if (status.ok()) {
    item.hostIdentifier = ident;
  } else if (ident.empty()) {
    ident = "<unknown>";
  }

  item.unixTime = osquery::getUnixTime();
  item.calendarTime = osquery::getAsciiTime();

  VLOG(1) << "Found results for query " << name << " for host: " << ident;
  status = logScheduledQueryLogItem(item);
  if (!status.ok()) {
    LOG(ERROR) << "Error logging the results of query \"" << query.query << "\""
               << ": " << status.toString();
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
    // Put the thread into an interruptable sleep without a config instance.
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
