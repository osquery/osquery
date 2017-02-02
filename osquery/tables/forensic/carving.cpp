/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/carver.h>
#include <osquery/core.h>
#include <osquery/dispatcher.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

void enumerateCarves(QueryData& results) {
  Row r;
  r["timestamp"] = INTEGER(time(nullptr));
  r["md5"] = "";
  r["carve"] = INTEGER(0);
  r["path"] = "/";
  results.push_back(r);
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

  if (context.constraints["carve"].exists(EQUALS) && paths.size() > 0) {
    Dispatcher::addService(std::make_shared<Carver>(paths));
  } else {
    // TODO: Is this necessary? I should be able to just return the db contents
    enumerateCarves(results);
  }

  return results;
}
}
}
