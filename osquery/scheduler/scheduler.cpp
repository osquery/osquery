// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/scheduler.h"

#include <climits>
#include <ctime>

#include <glog/logging.h>

#include "osquery/config.h"
#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/flags.h"
#include "osquery/logger.h"
#include "osquery/sql.h"

namespace osquery {

DEFINE_osquery_flag(string,
                    host_identifier,
                    "hostname",
                    "Field used to identify the host running osqueryd");

std::string getHostIdentifier(std::string hostIdFlag,
                              std::shared_ptr<DBHandle> db) {
  if (hostIdFlag == "uuid") {
    std::vector<std::string> results;
    auto status = db->Scan(kConfigurations, results);

    if (!status.ok()) {
      throw std::runtime_error("Failure scanning the database for the hostIdentifier field");
    }

    std::string hostId;
    bool present =
        (std::find(results.begin(), results.end(), "hostIdentifier") !=
         results.end());
    if (present) {
      status = db->Get(kConfigurations, "hostIdentifier", hostId);
      if (!status.ok()) {
        throw std::runtime_error("Could get the hostIdentifier field from the database");
      }
    } else {
      // There was no uuid stored in the database, generate one and store it.
      hostId = osquery::generateHostUuid();
      LOG(INFO) << "Using uuid " << hostId << " to identify this host.";
      db->Put(kConfigurations, "hostIdentifier", hostId);
    }
    return hostId;

  } else {
    // use the hostname as the default machine identifier
    return osquery::getHostname();
  }
}

void launchQueries(const std::vector<OsqueryScheduledQuery>& queries,
                   const int64_t& second) {
  for (const auto& q : queries) {
    if (second % q.interval == 0) {
      std::string hostIdentifier;
      try {
        hostIdentifier = getHostIdentifier(FLAGS_host_identifier, DBHandle::getInstance());
      }
      catch(std::exception& e){
        LOG(ERROR) << "Unable to access hostIdentifier in database: " << e.what() << "; Using hostname to "
                "identify this machine";
        hostIdentifier = osquery::getHostname();
      }

      LOG(INFO) << hostIdentifier << " is executing query: " << q.query;
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
        VLOG(1) << "Results found for query: \"" << q.query << "\"";
        ScheduledQueryLogItem item;
        item.diffResults = diff_results;
        item.name = q.name;
        item.hostIdentifier = hostIdentifier;
        item.unixTime = osquery::getUnixTime();
        item.calendarTime = osquery::getAsciiTime();
        auto s = logScheduledQueryLogItem(item);
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
