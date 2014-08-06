// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/scheduler.h"

#include <ctime>
#include <iostream>

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <glog/logging.h>

#include "osquery/config.h"
#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/logger.h"

#define SCHEDULER_INTERVAL 60

using namespace osquery::config;
namespace core = osquery::core;
namespace db = osquery::db;
namespace logger = osquery::logger;

namespace osquery { namespace scheduler {

void launchQueries(boost::asio::deadline_timer& t, int mins) {
  DLOG(INFO) << "launchQueries: " << mins;

  auto cfg = Config::getInstance();
  for (auto query : cfg->getScheduledQueries()) {
    if ((mins % query.interval) == 0) {
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
        auto status = dbQuery.addNewResults(
          query_results,
          diff_results,
          unix_time
        );
        if (!status.ok()) {
          LOG(ERROR) << "error adding new results to database: "
            << status.toString();
          continue;
        }

        db::ScheduledQueryLogItem item;
        item.diffResults = diff_results;
        item.name = query.name;
        logger::logScheduledQueryLogItem(item);
    }
  }

  ++mins;

  t.expires_at(
    t.expires_at() + boost::posix_time::seconds(SCHEDULER_INTERVAL)
  );
  t.async_wait(boost::bind(launchQueries, boost::ref(t), mins));
}

void initialize() {
  DLOG(INFO) << "osquery::scheduler::initialize";
  boost::asio::io_service io;

  time_t _time = time(0);
  struct tm *now = localtime(&_time);
  int mins = now->tm_min;

  boost::asio::deadline_timer t(
    io,
    boost::posix_time::seconds(SCHEDULER_INTERVAL)
  );

  t.async_wait(boost::bind(launchQueries, boost::ref(t), mins));

  io.run();
}

}}
