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

#include <glog/logging.h>

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/scheduler.h>

namespace osquery {

DEFINE_osquery_flag(string,
                    host_identifier,
                    "hostname",
                    "Field used to identify the host running osqueryd");

Status getHostIdentifier(std::string& ident) {
  std::shared_ptr<DBHandle> db;
  try {
    db = DBHandle::getInstance();
  } catch (const std::exception& e) {
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

void launchQueries(const std::vector<OsqueryScheduledQuery>& queries,
                   const int64_t& second) {
  for (const auto& q : queries) {
    if (second % q.interval == 0) {
      LOG(INFO) << "Executing query: " << q.query;
      int unix_time = std::time(0);
      auto sql = SQL(q.query);
      if (!sql.ok()) {
        LOG(ERROR) << "Error executing query (" << q.query
                   << "): " << sql.getMessageString();
        continue;
      }
      auto dbQuery = Query(q);
      DiffResults diff_results;
      auto status = dbQuery.addNewResults(sql.rows(), diff_results, unix_time);
      if (!status.ok()) {
        LOG(ERROR)
            << "Error adding new results to database: " << status.toString();
        continue;
      }

      if (diff_results.added.size() > 0 || diff_results.removed.size() > 0) {
        ScheduledQueryLogItem item;
        Status s;

        item.diffResults = diff_results;
        item.name = q.name;

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

        LOG(INFO) << "Found results for query " << q.name
                  << " for host: " << ident;
        s = logScheduledQueryLogItem(item);
        if (!s.ok()) {
          LOG(ERROR) << "Error logging the results of query \"" << q.query
                     << "\""
                     << ": " << s.toString();
        }
      }
    }
  }
}

void initializeScheduler() {
  DLOG(INFO) << "osquery::initializeScheduler";
  time_t t = time(0);
  struct tm* local = localtime(&t);
  unsigned long int second = local->tm_sec;
  auto cfg = Config::getInstance();
#ifdef OSQUERY_TEST_DAEMON
  // if we're testing the daemon, only iterate through 15 "seconds"
  static unsigned long int stop_at = second + 15;
#else
  // if this is production, count forever
  static unsigned long int stop_at = ULONG_MAX;
#endif
  for (; second <= stop_at; ++second) {
    launchQueries(cfg->getScheduledQueries(), second);
    sleep(1);
  }
}
}
