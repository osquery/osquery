// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <string>
#include <vector>

#include <sqlite3.h>

#include <boost/filesystem.hpp>

#include "osquery/database/results.h"

namespace osquery {

/**
 * @brief The version of osquery
 */
extern const std::string kVersion;
/// Use a macro for the version literal, set the kVersion symbol in the library.
#define VERSION "1.0.3"

/**
 * @brief Execute a query
 *
 * This is a lower-level version of osquery::SQL. Prefer to use osquery::SQL.
 *
 * @code{.cpp}
 *   std::string q = "SELECT * FROM time;";
 *   int i = 0;
 *   auto qd = query(q, i);
 *   if (i == 0) {
 *     for (const auto& each : qd) {
 *       for (const auto& it : each) {
 *         LOG(INFO) << it.first << ": " << it.second;
 *       }
 *     }
 *   } else {
 *     LOG(ERROR) << "Error: " << i;
 *   }
 * @endcode
 *
 * @param q the query to execute
 * @param error_return an int indicating the success or failure of the query
 *
 * @return the results of the query
 */
osquery::QueryData query(const std::string& q, int& error_return);

/**
 * @brief Execute a query on a specific database
 *
 * If you need to use a different database, other than the osquery default,
 * use this method and pass along a pointer to a SQLite3 database. This is
 * useful for testing.
 *
 * @param q the query to execute
 * @param error_return an int indicating the success or failure of the query
 * @param db the SQLite3 database the execute query q against
 *
 * @return the results of the query
 */
osquery::QueryData query(const std::string& q, int& error_return, sqlite3* db);

/**
 * @brief Return a fully configured sqlite3 database object
 *
 * An osquery database is basically just a SQLite3 database with several
 * virtual tables attached. This method is the main abstraction for creating
 * SQLite3 databases within osquery.
 *
 * @return a SQLite3 database with all virtual tables attached
 */
sqlite3* createDB();

/**
 * @brief Sets up various aspects of osquery execution state.
 *
 * osquery needs a few things to happen as soon as the executable begins
 * executing. initOsquery takes care of setting up the relevant parameters.
 * initOsquery should be called in an executable's `main()` function.
 *
 * @param argc the number of elements in argv
 * @param argv the command-line arguments passed to `main()`
 */
void initOsquery(int argc, char* argv[]);

/**
 * @brief Split a given string based on an optional deliminator.
 *
 * If no deliminator is supplied, the string will be split based on whitespace.
 *
 * @param s the string that you'd like to split
 * @param delim the delimiter which you'd like to split the string by
 *
 * @return a vector of strings which represent the split string that you
 * passed as the s parameter.
 */
std::vector<std::string> split(const std::string& s,
                               const std::string& delim = "\t ");

/**
 * @brief Getter for a host's current hostname
 *
 * @return a string representing the host's current hostname
 */
std::string getHostname();

/**
 * @brief Getter for the current time, in a human-readable format.
 *
 * @return the current date/time in the format: "Wed Sep 21 10:27:52 2011"
 */
std::string getAsciiTime();

/**
 * @brief Getter for the current unix time.
 *
 * @return an int representing the amount of seconds since the unix epoch
 */
int getUnixTime();

/**
 * @brief Return a vector of all home directories on the system
 *
 * @return a vector of strings representing the path of all home directories
 */
std::vector<boost::filesystem::path> getHomeDirectories();
}
