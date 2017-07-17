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

#include <osquery/logger.h>

#include "osquery/database/query.h"

namespace osquery {

uint64_t Query::getPreviousEpoch() {
  uint64_t epoch = 0;
  std::string raw;
  auto status = getDatabaseValue(kQueries, name_ + "epoch", raw);
  if (status.ok()) {
    epoch = std::stoul(raw);
  }
  return epoch;
}

Status Query::getPreviousQueryResults(QueryData& results) {
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

static inline void saveQuery(const std::string& name,
                             const std::string& query) {
  setDatabaseValue(kQueries, "query." + name, query);
}

bool Query::isNewQuery() {
  std::string query;
  getDatabaseValue(kQueries, "query." + name_, query);
  return (query != query_.query);
}

Status Query::addNewResults(const QueryData& qd, const uint64_t epoch) {
  DiffResults dr;
  return addNewResults(qd, epoch, dr, false);
}

Status Query::addNewResults(const QueryData& current_qd,
                            const uint64_t current_epoch,
                            DiffResults& dr,
                            bool calculate_diff) {
  // The current results are 'fresh' when not calculating a differential.
  bool fresh_results = !calculate_diff;
  if (!isQueryNameInDatabase()) {
    // This is the first encounter of the scheduled query.
    fresh_results = true;
    LOG(INFO) << "Storing initial results for new scheduled query: " << name_;
    saveQuery(name_, query_.query);
  } else if (getPreviousEpoch() != current_epoch) {
    fresh_results = true;
    LOG(INFO) << "New Epoch " << current_epoch << " for scheduled query "
              << name_;
  } else if (isNewQuery()) {
    // This query is 'new' in that the previous results may be invalid.
    LOG(INFO) << "Scheduled query has been updated: " + name_;
    saveQuery(name_, query_.query);
  }

  // Use a 'target' avoid copying the query data when serializing and saving.
  // If a differential is requested and needed the target remains the original
  // query data, otherwise the content is moved to the differential's added set.
  const auto* target_gd = &current_qd;
  if (!fresh_results && calculate_diff) {
    // Get the rows from the last run of this query name.
    QueryData previous_qd;
    auto status = getPreviousQueryResults(previous_qd);
    if (!status.ok()) {
      return status;
    }

    // Calculate the differential between previous and current query results.
    dr = diff(previous_qd, current_qd);
    fresh_results = (!dr.added.empty() || !dr.removed.empty());
  } else {
    dr.added = std::move(current_qd);
    target_gd = &dr.added;
  }

  if (fresh_results) {
    // Replace the "previous" query data with the current.
    std::string json;
    auto status = serializeQueryDataJSON(*target_gd, json);
    if (!status.ok()) {
      return status;
    }

    status = setDatabaseValue(kQueries, name_, json);
    if (!status.ok()) {
      return status;
    }

    status = setDatabaseValue(
        kQueries, name_ + "epoch", std::to_string(current_epoch));
    if (!status.ok()) {
      return status;
    }
  }
  return Status(0, "OK");
}
}
