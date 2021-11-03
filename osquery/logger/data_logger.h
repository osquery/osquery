/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>
#include <vector>

#include <boost/noncopyable.hpp>

#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/core/plugins/plugin.h>
#include <osquery/core/query.h>
#include <osquery/logger/logger.h>

namespace osquery {

enum class LoggerRelayMode { Sync, Async };

/// Set the verbose mode, changes Glog's sinking logic and will affect plugins.
void setVerboseLevel();

/**
 * @brief Start status logging to a buffer until the logger plugin is online.
 *
 * This will also call google::InitGoogleLogging. Use the default init_glog
 * to control this in tests to protect against calling the API twice.
 */
void initStatusLogger(const std::string& name, bool init_glog = true);

/**
 * @brief Initialize the osquery Logger facility by dumping the buffered status
 * logs and configuring status log forwarding.
 *
 * initLogger will disable the `BufferedLogSink` facility, dump any status logs
 * emitted between process start and this init call, then configure the new
 * logger facility to receive status logs.
 *
 * The `forward_all` control is used when buffering logs in extensions.
 * It is fine if the logger facility in the core app does not want to receive
 * status logs, but this is NOT an option in extensions/modules. All status
 * logs must be forwarded to the core.
 *
 * @param name The process name.
 */
void initLogger(const std::string& name);

/**
 * @brief Log a string using the default logger receiver.
 *
 * Note that this method should only be used to log results. If you'd like to
 * log normal osquery operations, use Google Logging.
 *
 * @param message the string to log
 * @param category a category/metadata key
 *
 * @return Status indicating the success or failure of the operation
 */
Status logString(const std::string& message, const std::string& category);

/**
 * @brief Log a string using a specific logger receiver.
 *
 * Note that this method should only be used to log results. If you'd like to
 * log normal osquery operations, use Google Logging.
 *
 * @param message the string to log
 * @param category a category/metadata key
 * @param receiver a string representing the log receiver to use
 *
 * @return Status indicating the success or failure of the operation
 */
Status logString(const std::string& message,
                 const std::string& category,
                 const std::string& receiver);

/**
 * @brief Log results of scheduled queries to the default receiver
 *
 * @param item a struct representing the results of a scheduled query
 *
 * @return Status indicating the success or failure of the operation
 */
Status logQueryLogItem(const QueryLogItem& item);

/**
 * @brief Log results of scheduled queries to a specified receiver
 *
 * @param item a struct representing the results of a scheduled query
 * @param receiver a string representing the log receiver to use
 *
 * @return Status indicating the success or failure of the operation
 */
Status logQueryLogItem(const QueryLogItem& item, const std::string& receiver);

/**
 * @brief Log raw results from a query (or a snapshot scheduled query).
 *
 * @param item the unmangled results from the query planner.
 *
 * @return Status indicating the success or failure of the operation
 */
Status logSnapshotQuery(const QueryLogItem& item);

/**
 * @brief Sink a set of buffered status logs.
 *
 * When the osquery daemon uses a watcher/worker set, the watcher's status logs
 * are accumulated in a buffered log sink. Well-performing workers should have
 * the set of watcher status logs relayed and sent to the configured logger
 * plugin.
 *
 * Status logs from extensions will be forwarded to the extension manager (core)
 * normally, but the watcher does not receive or send registry requests.
 * Extensions, the registry, configuration, and optional config/logger plugins
 * are all protected as a monitored worker.
 */
void relayStatusLogs(LoggerRelayMode relay_mode = LoggerRelayMode::Sync);

/// Inspect the number of internal-buffered status log lines.
size_t queuedStatuses();

/**
 * @brief Write a log line to the OS system log.
 *
 * There are occasional needs to log independently of the osquery logging
 * facilities. This allows a feature (not a table) to bypass all osquery
 * configuration and log to the OS system log.
 *
 * Linux/Darwin: this uses syslog's LOG_NOTICE.
 * Windows: This will end up inside the Facebook/osquery in the Windows
 * Event Log.
 */
void systemLog(const std::string& line);

/**
 * @brief Construct a custom prefix for each google log line
 *
 * With newer Google Log versions the log lines have acquired the year in their
 * prefix. We want to use the old format without it for now.
 */
void googleLogCustomPrefix(std::ostream& s,
                           const LogMessageInfo& l,
                           void* data);
} // namespace osquery
