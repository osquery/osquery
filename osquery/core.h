// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef OSQUERY_CORE_H
#define OSQUERY_CORE_H

#include <string>
#include <vector>

#include <sqlite3.h>

#include "osquery/database.h"

namespace osquery {
namespace core {

// aggregateQuery accepts a const reference to an std::string and returns a
// resultset of type QueryData.
osquery::db::QueryData aggregateQuery(const std::string& q, int& error_return);
osquery::db::QueryData aggregateQuery(const std::string& q,
                                      int& error_return,
                                      sqlite3* db);

// initOsquery sets up various aspects of osquery execution state. it should
// be called in an executable's main() function
void initOsquery(int argc, char* argv[]);

// Split a given string based on an optional deliminator. If not deliminator is
// supplied, the string will be split based on whitespace.
std::vector<std::string> split(const std::string& s);
std::vector<std::string> split(const std::string& s, const std::string& delim);

// getHostname returns a std::string which contains the current host's hostname
std::string getHostname();

// getAsciiTime() returns a string containing the current time in the following
// format: Wed Sep 21 10:27:52 2011
std::string getAsciiTime();

// getUnixTime() returns an int which represents the current time since the
// unix epoch
int getUnixTime();
}
}

#endif /* OSQUERY_CORE_H */
