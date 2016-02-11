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

/////////////////////////////////////////////////////////////////////////////
// Data access methods
/////////////////////////////////////////////////////////////////////////////

Status Query::getPreviousQueryResults(QueryData& results) {
  return getPreviousQueryResults(results, DBHandle::getInstance());
}

Status Query::getPreviousQueryResults(QueryData& results, DBHandleRef db) {
  if (!isQueryNameInDatabase()) {
    return Status(0, "Query name not found in database");
  }

  std::string raw;
  auto status = db->Get(kQueries, name_, raw);
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
  return getStoredQueryNames(DBHandle::getInstance());
}

std::vector<std::string> Query::getStoredQueryNames(DBHandleRef db) {
  std::vector<std::string> results;
  db->Scan(kQueries, results);
  return results;
}

bool Query::isQueryNameInDatabase() {
  return isQueryNameInDatabase(DBHandle::getInstance());
}

bool Query::isQueryNameInDatabase(DBHandleRef db) {
  auto names = Query::getStoredQueryNames(db);
  return std::find(names.begin(), names.end(), name_) != names.end();
}

Status Query::addNewResults(const osquery::QueryData& qd) {
  return addNewResults(qd, DBHandle::getInstance());
}

Status Query::addNewResults(const QueryData& qd, DBHandleRef db) {
  DiffResults dr;
  return addNewResults(qd, dr, false, db);
}

Status Query::addNewResults(const QueryData& qd, DiffResults& dr) {
  return addNewResults(qd, dr, true, DBHandle::getInstance());
}

Status Query::addNewResults(const QueryData& current_qd,
                            DiffResults& dr,
                            bool calculate_diff,
                            DBHandleRef db) {
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

    status = db->Put(kQueries, name_, json);
    if (!status.ok()) {
      return status;
    }
  }
  return Status(0, "OK");
}
}
