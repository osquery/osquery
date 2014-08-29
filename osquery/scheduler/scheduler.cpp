// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/scheduler.h"

#include <ctime>

#include <glog/logging.h>

#include "osquery/config.h"
#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/logger.h"

#define SCHEDULER_INTERVAL 1

using namespace osquery::config;
namespace core = osquery::core;
namespace db = osquery::db;
namespace logger = osquery::logger;

namespace osquery {
namespace scheduler {

void launchQueries(const osquery::config::scheduledQueries_t& queries, const int64_t& minute) {
  LOG(INFO) << "launchQueries: " << minute;
  for (const auto& query : queries) {
    if (minute % query.interval == 0) {
      VLOG(1) << "executing query: " << query.query;
      int unix_time = std::time(0);
      int err;
      auto query_results = core::aggregateQuery(query.query, err);
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
        db::ScheduledQueryLogItem item;
        item.diffResults = diff_results;
        item.name = query.name;
        item.hostname = osquery::core::getHostname();
        item.unixTime = osquery::core::getUnixTime();
        item.calendarTime = osquery::core::getAsciiTime();
        logger::logScheduledQueryLogItem(item);
      }
    }
  }
}

void initialize() {
  DLOG(INFO) << "osquery::scheduler::initialize";
  time_t t = time(0);
  struct tm *local = localtime(&t);
  static int64_t minute = local->tm_min;
  auto cfg = Config::getInstance();
  for (;; ++minute) {
    launchQueries(cfg->getScheduledQueries(), minute);
    sleep(SCHEDULER_INTERVAL);
  }
}
}
}
