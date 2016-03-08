/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <algorithm>

#include "osquery/database/query.h"

namespace osquery {

Status Query::getPreviousQueryResults(QueryData& results) {
  if (!isQueryNameInDatabase()) {
    return Status(0, "Query name not found in database");
  }

  std::string raw;
  auto status = getDatabaseValue(kQueries, name_, raw);
  if (!status.ok()) {
    return status;
  }

  status = deserializeQueryDataJSON(raw, results);
  if (!status.ok()) {
    return status;
  }
  return Status(0, "OK");
}

std::vector<std::string> Query::getStoredQueryNames() {
  std::vector<std::string> results;
  scanDatabaseKeys(kQueries, results);
  return results;
}

bool Query::isQueryNameInDatabase() {
  auto names = Query::getStoredQueryNames();
  return std::find(names.begin(), names.end(), name_) != names.end();
}

Status Query::addNewResults(const QueryData& qd) {
  DiffResults dr;
  return addNewResults(qd, dr, false);
}

Status Query::addNewResults(const QueryData& qd, DiffResults& dr) {
  return addNewResults(qd, dr, true);
}

Status Query::addNewResults(const QueryData& current_qd,
                            DiffResults& dr,
                            bool calculate_diff) {
  // Get the rows from the last run of this query name.
  QueryData previous_qd;
  auto status = getPreviousQueryResults(previous_qd);
  if (!status.ok()) {
    return status;
  }

  // Calculate the differential between previous and current query results.
  if (calculate_diff) {
    dr = diff(previous_qd, current_qd);
  }

  if (previous_qd.size() == 0 || dr.added.size() != 0 ||
      dr.removed.size() != 0) {
    // Replace the "previous" query data with the current.
    std::string json;
    status = serializeQueryDataJSON(current_qd, json);
    if (!status.ok()) {
      return status;
    }

    status = setDatabaseValue(kQueries, name_, json);
    if (!status.ok()) {
      return status;
    }
  }
  return Status(0, "OK");
}
}
