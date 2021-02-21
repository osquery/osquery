/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/status/status.h>

#include <atomic>
#include <set>
#include <string>

namespace osquery {

/// Prefix used for the temp FS where carved files are stored.
const std::string kCarvePathPrefix = "osquery_carve_";

/// Prefix applied to the file carve tar archive.
const std::string kCarveNamePrefix = "carve_";

/// Database prefix used to directly access and manipulate our carver entries.
const std::string kCarverDBPrefix = "carves.";

/// Internal carver 'status' indicating a completed carve.
const std::string kCarverStatusSuccess = "SUCCESS";

/// Internal carver 'status' indicating a carve request scheduled.
const std::string kCarverStatusScheduled = "SCHEDULED";

/**
 * @brief This flag is an optimization attempt used by the CarverRunner.
 *
 * When osquery starts, if the carver is enabled, the CarverRunner will scan
 * for pending carves. After all are started, it will set this pending flag to
 * false. Any carve requests will set it to true.
 *
 * CarverRunner threads start every 60 seconds. It is wasteful to start and stop
 * the thread if there are no pending carves. This flag allows us to skip
 * starting the thread.
 */
extern std::atomic<bool> kCarverPendingCarves;

/// Update an attribute for a given carve GUID.
void updateCarveValue(const std::string& guid,
                      const std::string& key,
                      const std::string& value);

/// Returns a UUID.
std::string createCarveGuid();

/**
 * @brief Request a file carve of the given paths.
 *
 * The actual carving is deferred until the scheduler dispatches the request.
 * This is to prevent several carves happening in parallel and to prevent carves
 * from unexpectedly blocking query execution. We do not want to wait for remote
 * servies to return before a query completes in this case.
 *
 * @param paths A set of paths (directories and files) to carve.
 * @param request_id A string identifier to be included in the carve response.
 * @param carve_guid An output GUID identifying the carve request.
 *
 * @return A status returning if the carves were scheduled successfully.
 */
Status carvePaths(const std::set<std::string>& paths,
                  const std::string& request_id,
                  std::string& carve_guid);
} // namespace osquery
