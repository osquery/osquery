/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <map>
#include <string>
#include <vector>

#include <osquery/flags.h>
#include <osquery/query.h>

namespace osquery {

/// Show all tables and exit the shell.
DECLARE_bool(L);

/// Select all from a table an exit the shell.
DECLARE_string(A);

/// The shell may request execution of all queries in a pack immediately.
DECLARE_string(pack);

/// The shell may need to disable events for fast operations.
DECLARE_bool(disable_events);

/**
 * @brief Run an interactive SQL query shell.
 *
 * @code{.cpp}
 *   // Copyright 2004-present Facebook. All Rights Reserved.
 *   #include <osquery/core.h>
 *   #include <osquery/devtools.h>
 *
 *   int main(int argc, char *argv[]) {
 *     osquery::initOsquery(argc, argv);
 *     return osquery::launchIntoShell(argc, argv);
 *   }
 * @endcode
 *
 * @param argc the number of elements in argv
 * @param argv the command-line flags
 *
 * @return an int which represents the "return code"
 */
int launchIntoShell(int argc, char** argv);

/**
 * @brief Pretty print a QueryData object
 *
 * This is a helper method which called osquery::beautify on the supplied
 * QueryData object and prints the results to stdout.
 *
 * @param results The QueryData object to print
 * @param columns The order of the keys (since maps are unordered)
 * @param lengths A mutable set of column lengths
 */
void prettyPrint(const QueryData& results,
                 const std::vector<std::string>& columns,
                 std::map<std::string, size_t>& lengths);

/**
 * @brief JSON print a QueryData object
 *
 * This is a helper method which allows a shell or other tool to print results
 * in a JSON format.
 *
 * @param q The QueryData object to print
 */
void jsonPrint(const QueryData& q);

/**
 * @brief Compute a map of metadata about the supplied QueryData object
 *
 * @param r A row to analyze
 * @param lengths A mutable set of column lengths
 * @param use_columns Calulate lengths of column names or values
 *
 * @return A map of string to int such that the key represents the "column" in
 * the supplied QueryData and the int represents the length of the longest key
 */
void computeRowLengths(const Row& r,
                       std::map<std::string, size_t>& lengths,
                       bool use_columns = false);

/**
 * @brief Generate the separator string for query results
 *
 * @param lengths The data returned from computeQueryDataLengths
 * @param columns The order of the keys (since maps are unordered)
 *
 * @return A string, with a newline, representing your separator
 */
std::string generateToken(const std::map<std::string, size_t>& lengths,
                          const std::vector<std::string>& columns);

/**
 * @brief Generate the header string for query results
 *
 * @param lengths The data returned from computeQueryDataLengths
 * @param columns The order of the keys (since maps are unordered)
 *
 * @return A string, with a newline, representing your header
 */
std::string generateHeader(const std::map<std::string, size_t>& lengths,
                           const std::vector<std::string>& columns);

/**
 * @brief Generate a row string for query results
 *
 * @param r A row to analyze
 * @param lengths The data returned from computeQueryDataLengths
 * @param columns The order of the keys (since maps are unordered)
 *
 * @return A string, with a newline, representing your row
 */
std::string generateRow(const Row& r,
                        const std::map<std::string, size_t>& lengths,
                        const std::vector<std::string>& columns);
}
