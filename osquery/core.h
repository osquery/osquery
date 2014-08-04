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

// Split a given string based on whitespace
std::vector<std::string> split(const std::string& s);
std::vector<std::string> split(const std::string& s,
  const std::string& regexp);

// Join a given string based on a given deliminator.
std::string join(const std::vector<std::string>& v, const std::string& delim);

// trim the surrounding whitespace from a string
std::string &ltrim(std::string &s);
std::string &rtrim(std::string &s);
std::string &trim(std::string &s);

}}

#endif /* OSQUERY_CORE_H */
