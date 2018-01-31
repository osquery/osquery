/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/algorithm/string/join.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/dispatcher.h>
#include <osquery/distributed.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/carver/carver.h"
#include "osquery/core/json.h"

namespace pt = boost::property_tree;

#define DECLARE_TABLE_IMPLEMENTATION
#include <generated/tables/tbl_carves_defs.hpp>

namespace osquery {

DECLARE_bool(disable_carver);

std::string generateNewUUID();

namespace tables {

void enumerateCarves(QueryData& results) {
  std::vector<std::string> carves;
  scanDatabaseKeys(kCarveDbDomain, carves, kCarverDBPrefix);

  for (const auto& carveGuid : carves) {
    std::string carve;
    auto s = getDatabaseValue(kCarveDbDomain, carveGuid, carve);
    if (!s.ok()) {
      VLOG(1) << "Failed to retrieve carve GUID";
      continue;
    }

    pt::ptree tree;
    try {
      std::stringstream ss(carve);
      pt::read_json(ss, tree);
    } catch (const pt::ptree_error& e) {
      VLOG(1) << "Failed to parse carve entries: " << e.what();
      return;
    }

    Row r;
    r["time"] = BIGINT(tree.get<int>("time"));
    r["size"] = INTEGER(tree.get<int>("size"));
    r["sha256"] = SQL_TEXT(tree.get<std::string>("sha256"));
    r["carve_guid"] = SQL_TEXT(tree.get<std::string>("carve_guid"));
    r["status"] = SQL_TEXT(tree.get<std::string>("status"));
    r["carve"] = INTEGER(0);
    r["path"] = SQL_TEXT(tree.get<std::string>("path"));
    results.push_back(r);
  }
}

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

  if (context.constraints["carve"].exists(EQUALS) && paths.size() > 0 &&
      !FLAGS_disable_carver) {
    carvePaths(paths);
  }
  enumerateCarves(results);

  return results;
}
}
}
