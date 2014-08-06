// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef OSQUERY_CORE_SQLITE_UTIL_H
#define OSQUERY_CORE_SQLITE_UTIL_H

#include <string>
#include <vector>

#include "osquery/database.h"
#include "osquery/sqlite3.h"

namespace osquery { namespace core {

// the callback for populating a std::vector<row> set of results. "argument"
// should be a non-const reference to a std::vector<row>
int query_data_callback(void *argument, int argc, char *argv[], char *column[]);

// Return a fully configured sqlite3 database object
sqlite3* createDB();

}}

#endif /* OSQUERY_CORE_SQLITE_UTIL_H */
