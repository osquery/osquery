// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/scheduler.h"

#include <climits>
#include <ctime>

#include <glog/logging.h>

#include "osquery/config.h"
#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/dispatcher.h"
#include "osquery/logger.h"
#include "osquery/sql.h"

namespace osquery {

class ScheduledQueryRunnable : public apache::thrift::concurrency::Runnable {
 public:
  ScheduledQueryRunnable(const OsqueryScheduledQuery& q) : _query(q) {}

  virtual void run() {
    LOG(INFO) << "executing query: " << _query.query;
    int unix_time = std::time(0);
    auto sql = SQL(_query.query);
    if (!sql.ok()) {
      LOG(ERROR) << "error executing query (" << _query.query
                 << "): " << sql.getMessageString();
      return;
    }
    auto dbQuery = Query(_query);
    DiffResults diff_results;
    auto status = dbQuery.addNewResults(sql.rows(), diff_results, unix_time);
    if (!status.ok()) {
      LOG(ERROR)
          << "error adding new results to database: " << status.toString();
      return;
    }

    if (diff_results.added.size() > 0 || diff_results.removed.size() > 0) {
      VLOG(1) << "Results found for query: \"" << _query.query << "\"";
      ScheduledQueryLogItem item;
      item.diffResults = diff_results;
      item.name = _query.name;
      item.hostname = osquery::getHostname();
      item.unixTime = osquery::getUnixTime();
      item.calendarTime = osquery::getAsciiTime();
      auto s = logScheduledQueryLogItem(item);
      if (!s.ok()) {
        LOG(ERROR) << "Error logging the results of query \"" << _query.query
                   << "\""
                   << ": " << s.toString();
      }
    }
  }

 private:
  OsqueryScheduledQuery _query;
};

void launchQueries(const std::vector<OsqueryScheduledQuery>& queries,
                   const int64_t& second) {
  LOG(INFO) << "launchQueries: " << second;
  for (const auto& q : queries) {
    if (second % q.interval == 0) {
      auto& d = Dispatcher::getInstance();
      LOG(INFO) << "total count of tasks on the thread pool: "
                << d.totalTaskCount();
      d.add(std::make_shared<ScheduledQueryRunnable>(q));
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
