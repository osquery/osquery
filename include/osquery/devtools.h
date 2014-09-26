// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <string>

#include "osquery/database/results.h"

namespace osquery {

/**
 * @brief Run an interactive SQL query shell.
 *
 * @code{.cpp}
 *   // Copyright 2004-present Facebook. All Rights Reserved.
 *   #include "osquery/core.h"
 *   #include "osquery/devtools.h"
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
 * @brief Generate a pretty representation of a QueryData object
 *
 * @return The beautified string representation of the supplied QueryData
 * @param order The order of the keys (since maps are unordered)
 */
std::string beautify(const QueryData& q, const std::vector<std::string>& order);

/**
 * @brief Pretty print a QueryData object
 *
 * This is a helper method which called osquery::beautify on the supplied
 * QueryData object and prints the results to stdout.
 *
 * @param q The QueryData object to print
 * @param order The order of the keys (since maps are unordered)
 */
void prettyPrint(const QueryData& q, const std::vector<std::string>& order);

/**
 * @brief Compute a map of metadata about the supplied QueryData object
 *
 * @param q The QueryData object to analyze
 *
 * @return A map of string to int such that the key represents the "column" in
 * the supplied QueryData and the int represents the length of the longest key
 */
std::map<std::string, int> computeQueryDataLengths(const QueryData& q);

/**
 * @brief Generate the separator string for query results
 *
 * @param lengths The data returned from computeQueryDataLengths
 * @param order The order of the keys (since maps are unordered)
 *
 * @return A string, with a newline, representing your separator
 */
std::string generateSeparator(const std::map<std::string, int>& lengths,
                              const std::vector<std::string>& order);

/**
 * @brief Generate the header string for query results
 *
 * @param lengths The data returned from computeQueryDataLengths
 * @param order The order of the keys (since maps are unordered)
 *
 * @return A string, with a newline, representing your header
 */
std::string generateHeader(const std::map<std::string, int>& lengths,
                           const std::vector<std::string>& order);

/**
 * @brief Generate a row string for query results
 *
 * @param lengths The data returned from computeQueryDataLengths
 * @param order The order of the keys (since maps are unordered)
 *
 * @return A string, with a newline, representing your row
 */
std::string generateRow(const Row& r,
                        const std::map<std::string, int>& lengths,
                        const std::vector<std::string>& order);
}
