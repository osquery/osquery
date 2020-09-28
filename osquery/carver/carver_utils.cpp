/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/system/time.h>

#include <osquery/carver/carver_utils.h>

namespace osquery {

CLI_FLAG(bool,
         disable_carver,
         true,
         "Disable the osquery file carver (default true)");

std::atomic<bool> kCarverPendingCarves{true};

/// Helper function to update values related to a carve
void updateCarveValue(const std::string& guid,
                      const std::string& key,
                      const std::string& value) {
  std::string carve;
  auto s = getDatabaseValue(kCarves, kCarverDBPrefix + guid, carve);
  if (!s.ok()) {
    VLOG(1) << "Failed to update status of carve in database " << guid;
    return;
  }

  JSON tree;
  s = tree.fromString(carve);
  if (!s.ok()) {
    VLOG(1) << "Failed to parse carve entries: " << s.what();
    return;
  }

  tree.add(key, value);

  std::string out;
  s = tree.toString(out);
  if (!s.ok()) {
    VLOG(1) << "Failed to serialize carve entries: " << s.what();
  }

  s = setDatabaseValue(kCarves, kCarverDBPrefix + guid, out);
  if (!s.ok()) {
    VLOG(1) << "Failed to update status of carve in database " << guid;
  }
}

Status carvePaths(const std::set<std::string>& paths) {
  auto guid = generateNewUUID();

  JSON tree;
  tree.add("carve_guid", guid);
  tree.add("time", getUnixTime());
  tree.add("status", kCarverStatusScheduled);
  tree.add("sha256", "");
  tree.add("size", -1);

  if (paths.size() > 1) {
    tree.add("path", osquery::join(paths, ","));
  } else {
    tree.add("path", *(paths.begin()));
  }

  std::string out;
  auto s = tree.toString(out);
  if (!s.ok()) {
    VLOG(1) << "Failed to serialize carve paths: " << s.what();
    return s;
  }

  kCarverPendingCarves = true;
  return setDatabaseValue(kCarves, kCarverDBPrefix + guid, out);
}
} // namespace osquery
