// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "osquery/status.h"

namespace osquery {
namespace config {

// OsqueryScheduledQuery represents the relevant parameters of a scheduled query
struct OsqueryScheduledQuery {
  // name represents the "name" of a query
  std::string name;

  // query represents the actual SQL query
  std::string query;

  // interval represents how often the query should be executed, in minutes
  int interval;

  // equals operator
  bool operator==(const OsqueryScheduledQuery& comp) const {
    return (comp.name == name) && (comp.query == query) &&
           (comp.interval == interval);
  }

  // not equals operator
  bool operator!=(const OsqueryScheduledQuery& comp) const {
    return !(*this == comp);
  }
};

// typedef so that we can say OsqueryScheduledQuery instead of
// struct OsqueryScheduledQuery
typedef struct OsqueryScheduledQuery OsqueryScheduledQuery;

// scheduledQueries_t is a typedef for a vector of OsqueryScheduledQuery's. This
// is just here for the sake of conciseness
typedef std::vector<OsqueryScheduledQuery> scheduledQueries_t;

// OsqueryConfig is a native representation of osquery configuration data
struct OsqueryConfig {
  // scheduledQueries is a vector of all of the queries that are scheduled to
  // execute
  scheduledQueries_t scheduledQueries;
};

// kDefaultConfigRetriever is a string which represents the default retriever
// to be used in the event that one is not specified via flags
extern const std::string kDefaultConfigRetriever;

// Config is a singleton that exposes accessors to osquery's configuration data
class Config {
 public:
  // getInstance returns a singleton instance of Config.
  static std::shared_ptr<Config> getInstance();

  // getScheduledQueries returns a vector of OsqueryScheduledQuery's which
  // represent the queries that are to be executed
  scheduledQueries_t getScheduledQueries();

 private:
  // since instances of Config should only be created via getInstance(),
  // Config's constructor is private
  Config();

  // genConfig() is a symbol that is satisfied by the config plugin that gets
  // compiled with osquery
  static osquery::Status genConfig(OsqueryConfig& conf);

 private:
  // cfg_ is the private member that stores the raw osquery config data in a
  // native format
  OsqueryConfig cfg_;
};
}
}
