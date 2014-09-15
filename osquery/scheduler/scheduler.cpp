// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/scheduler.h"

#include <climits>
#include <ctime>

#include <glog/logging.h>

#include "osquery/config.h"
#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/logger.h"

namespace db = osquery::db;

namespace osquery {
namespace scheduler {

void launchQueries(const std::vector<OsqueryScheduledQuery>& queries,
                   const int64_t& second) {
  LOG(INFO) << "launchQueries: " << second;
  for (const auto& query : queries) {
    if (second % query.interval == 0) {
      LOG(INFO) << "executing query: " << query.query;
      int unix_time = std::time(0);
      int err;
      auto query_results = aggregateQuery(query.query, err);
      if (err != 0) {
        LOG(ERROR) << "error executing query: " << query.query;
        continue;
      }
      auto dbQuery = db::Query(query);
      db::DiffResults diff_results;
      auto status =
          dbQuery.addNewResults(query_results, diff_results, unix_time);
      if (!status.ok()) {
        LOG(ERROR)
            << "error adding new results to database: " << status.toString();
        continue;
      }

      if (diff_results.added.size() > 0 || diff_results.removed.size() > 0) {
        VLOG(1) << "Results found for query: \"" << query.query << "\"";
        db::ScheduledQueryLogItem item;
        item.diffResults = diff_results;
        item.name = query.name;
        item.hostname = osquery::getHostname();
        item.unixTime = osquery::getUnixTime();
        item.calendarTime = osquery::getAsciiTime();
        auto s = logScheduledQueryLogItem(item);
        if (!s.ok()) {
          LOG(ERROR) << "Error logging the results of query \"" << query.query
                     << "\""
                     << ": " << s.toString();
        }
      }
    }
  }
}

void initialize() {
  DLOG(INFO) << "osquery::scheduler::initialize";
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
}
