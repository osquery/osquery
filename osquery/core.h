// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef OSQUERY_CORE_H
#define OSQUERY_CORE_H

#include <string>
#include <vector>

#include "osquery/database.h"
#include "osquery/sqlite3.h"

namespace osquery { namespace core {

// aggregateQuery accepts a const reference to an std::string and returns a
// resultset of type QueryData.
osquery::db::QueryData
aggregateQuery(const std::string& q, int& error_return);
osquery::db::QueryData
aggregateQuery(const std::string& q, int& error_return, sqlite3* db);

// initOsquery sets up various aspects of osquery execution state. it should
// be called in an executable's main() function
void initOsquery(int argc, char *argv[]);

}}

#endif /* OSQUERY_CORE_H */
