// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <future>
#include <string>
#include <vector>

#include "osquery/status.h"
#include "osquery/database.h"

namespace osquery {

/**
 * @brief A string which represents the default logger receiver
 *
 * The logger plugin that you use to define your config receiver can be
 * defined via a command-line flag, however, if you don't define a logger
 * plugin to use via the command-line, then the logger receiver which is
 * represented by the string stored kDefaultLogReceiverName will be used.
 */
extern const std::string kDefaultLogReceiverName;

/**
 * @brief Log a string using the default logger receiver.
 *
 * Note that this method should only be used to log results. If you'd like to
 * log normal osquery operations, use Google Logging.
 *
 * @param s the string to log
 *
 * @return an instance of osquery::Status, indicating the success or failure
 * of the operation.
 */
osquery::Status logString(const std::string& s);

/**
 * @brief Log a string using a specific logger receiver.
 *
 * Note that this method should only be used to log results. If you'd like to
 * log normal osquery operations, use Google Logging.
 *
 * @param s the string to log
 * @param receiver a string representing the log receiver to use
 *
 * @return an instance of osquery::Status, indicating the success or failure
 * of the operation.
 */
osquery::Status logString(const std::string& s, const std::string& receiver);

/**
 * @brief Directly log results of scheduled queries to the default receiver
 *
 * @param item a struct representing the results of a scheduled query
 *
 * @return an instance of osquery::Status, indicating the success or failure
 * of the operation.
 */
osquery::Status logScheduledQueryLogItem(
    const osquery::db::ScheduledQueryLogItem& item);

/**
 * @brief Directly log results of scheduled queries to a specified receiver
 *
 * @param item a struct representing the results of a scheduled query
 * @param receiver a string representing the log receiver to use
 *
 * @return an instance of osquery::Status, indicating the success or failure
 * of the operation.
 */
osquery::Status logScheduledQueryLogItem(
    const osquery::db::ScheduledQueryLogItem& item,
    const std::string& receiver);
}
