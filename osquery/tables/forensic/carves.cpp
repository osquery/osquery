/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/carver/carver_utils.h>
#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/database/database.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/json/json.h>

namespace osquery {

DECLARE_bool(disable_carver);

namespace tables {
namespace {

inline void stringToRow(const std::string& key, Row& r, JSON& tree) {
  if (tree.doc().HasMember(key) && tree.doc()[key].IsString()) {
    r[key] = tree.doc()[key].GetString();
  }
}

void enumerateCarves(QueryData& results, const std::string& new_guid) {
  std::vector<std::string> carves;
  scanDatabaseKeys(kCarves, carves, kCarverDBPrefix);

  for (const auto& carveGuid : carves) {
    std::string carve;
    auto s = getDatabaseValue(kCarves, carveGuid, carve);
    if (!s.ok()) {
      VLOG(1) << "Failed to retrieve carve GUID";
      continue;
    }

    JSON tree;
    s = tree.fromString(carve);
    if (!s.ok() || !tree.doc().IsObject()) {
      VLOG(1) << "Failed to parse carve entries: " << s.getMessage();
      return;
    }

    Row r;
    if (tree.doc().HasMember("time")) {
      r["time"] = INTEGER(tree.doc()["time"].GetUint64());
    }

    if (tree.doc().HasMember("size")) {
      r["size"] = INTEGER(tree.doc()["size"].GetInt());
    }

    stringToRow("sha256", r, tree);
    stringToRow("carve_guid", r, tree);
    stringToRow("request_id", r, tree);
    stringToRow("status", r, tree);
    stringToRow("path", r, tree);

    // This table can be used to request a new carve.
    // If this is the case then return this single result.
    auto new_request = (!new_guid.empty() && new_guid == r["carve_guid"]);
    r["carve"] = INTEGER((new_request) ? 1 : 0);

    results.push_back(r);
  }
}
} // namespace

QueryData genCarves(QueryContext& context) {
  QueryData results;

  auto paths = context.constraints["path"].getAll(EQUALS);
  context.expandConstraints(
      "path",
      LIKE,
      paths,
      ([&](const std::string& pattern, std::set<std::string>& out) {
        std::vector<std::string> patterns;
        auto status =
            resolveFilePattern(pattern, patterns, GLOB_ALL | GLOB_NO_CANON);
        if (status.ok()) {
          for (const auto& resolved : patterns) {
            out.insert(resolved);
          }
        }
        return status;
      }));

  // A carve is requested if carve = 1 exists in the predicate.
  auto requests = context.constraints["carve"].getAll<int>(EQUALS);
  auto carve_requested = requests.find(1) != requests.end();

  std::string new_carve_guid;
  if (!FLAGS_disable_carver && carve_requested && !paths.empty()) {
    // TODO(6727): This should introspect into the requesting action.
    // Indicate if the initiator is a distributed query or the schedule.
    auto request_id = createCarveGuid();
    carvePaths(paths, request_id, new_carve_guid);
  }
  enumerateCarves(results, new_carve_guid);

  return results;
}
}
}
