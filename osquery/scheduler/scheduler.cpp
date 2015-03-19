/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <climits>
#include <ctime>
#include <random>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/scheduler.h>

namespace osquery {

FLAG(string,
     host_identifier,
     "hostname",
     "Field used to identify the host running osquery (hostname, uuid)");

FLAG(int32, schedule_splay_percent, 10, "Percent to splay config times");

Status getHostIdentifier(std::string& ident) {
  std::shared_ptr<DBHandle> db;
  try {
    db = DBHandle::getInstance();
  } catch (const std::runtime_error& e) {
    return Status(1, e.what());
  }

  if (FLAGS_host_identifier == "uuid") {
    std::vector<std::string> results;
    auto status = db->Scan(kConfigurations, results);

    if (!status.ok()) {
      LOG(ERROR) << "Could not access database, using hostname as the host "
                    "identifier.";
      ident = osquery::getHostname();
      return Status(0, "OK");
    }

    if (std::find(results.begin(), results.end(), "hostIdentifier") !=
        results.end()) {
      status = db->Get(kConfigurations, "hostIdentifier", ident);
      if (!status.ok()) {
        LOG(ERROR) << "Could not access database, using hostname as the host "
                      "identifier.";
        ident = osquery::getHostname();
      }
      return status;
    } else {
      // There was no uuid stored in the database, generate one and store it.
      ident = osquery::generateHostUuid();
      LOG(INFO) << "Using uuid " << ident << " to identify this host.";
      return db->Put(kConfigurations, "hostIdentifier", ident);
    }
  } else {
    // use the hostname as the default machine identifier
    ident = osquery::getHostname();
    return Status(0, "OK");
  }
}

void launchQuery(const OsqueryScheduledQuery& query) {
  LOG(INFO) << "Executing query: " << query.query;
  int unix_time = std::time(0);
  auto sql = SQL(query.query);
  if (!sql.ok()) {
    LOG(ERROR) << "Error executing query (" << query.query
               << "): " << sql.getMessageString();
    return;
  }

  auto dbQuery = Query(query);
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
  Status s;

  item.diffResults = diff_results;
  item.name = query.name;

  std::string ident;
  s = getHostIdentifier(ident);
  if (s.ok()) {
    item.hostIdentifier = ident;
  } else {
    LOG(ERROR) << "Error getting the host identifier";
    if (ident.empty()) {
      ident = "<unknown>";
    }
  }

  item.unixTime = osquery::getUnixTime();
  item.calendarTime = osquery::getAsciiTime();

  LOG(INFO) << "Found results for query " << query.name
            << " for host: " << ident;
  s = logScheduledQueryLogItem(item);
  if (!s.ok()) {
    LOG(ERROR) << "Error logging the results of query \"" << query.query << "\""
               << ": " << s.toString();
  }
}

void launchQueries(const std::vector<OsqueryScheduledQuery>& queries,
                   const int64_t& second) {
  for (const auto& q : queries) {
    if (second % q.interval == 0) {
      launchQuery(q);
    }
  }
}

int splayValue(int original, int splayPercent) {
  if (splayPercent <= 0 || splayPercent > 100) {
    return original;
  }

  float percent_to_modify_by = (float)splayPercent / 100;
  int possible_difference = original * percent_to_modify_by;
  int max_value = original + possible_difference;
  int min_value = original - possible_difference;

  if (max_value == min_value) {
    return max_value;
  }

  std::default_random_engine generator;
  std::uniform_int_distribution<int> distribution(min_value, max_value);
  return distribution(generator);
}

void initializeScheduler() {
  DLOG(INFO) << "osquery::initializeScheduler";
  time_t t = time(0);
  struct tm* local = localtime(&t);
  unsigned long int second = local->tm_sec;

#ifdef OSQUERY_TEST_DAEMON
  // if we're testing the daemon, only iterate through 15 "seconds"
  static unsigned long int stop_at = second + 15;
#else
  // if this is production, count forever
  static unsigned long int stop_at = ULONG_MAX;
#endif

  // Iterate over scheduled queryies and add a splay to each.
  auto schedule = Config::getScheduledQueries();
  for (auto& q : schedule) {
    auto old_interval = q.interval;
    auto new_interval = splayValue(old_interval, FLAGS_schedule_splay_percent);
    VLOG(1) << "Splay changing the interval for " << q.name << " from  "
            << old_interval << " to " << new_interval;
    q.interval = new_interval;
  }

  for (; second <= stop_at; ++second) {
    launchQueries(schedule, second);
    ::sleep(1);
  }
}
}
