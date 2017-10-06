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
#include <string>
#include <vector>

#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/query.h>

#include "osquery/core/json.h"

namespace pt = boost::property_tree;
namespace rj = rapidjson;

namespace osquery {

DECLARE_bool(decorations_top_level);

uint64_t Query::getPreviousEpoch() const {
  uint64_t epoch = 0;
  std::string raw;
  auto status = getDatabaseValue(kQueries, name_ + "epoch", raw);
  if (status.ok()) {
    epoch = std::stoull(raw);
  }
  return epoch;
}

uint64_t Query::getQueryCounter(bool new_query) const {
  uint64_t counter = 0;
  if (new_query) {
    return counter;
  }

  std::string raw;
  auto status = getDatabaseValue(kQueries, name_ + "counter", raw);
  if (status.ok()) {
    counter = std::stoull(raw) + 1;
  }
  return counter;
}

Status Query::getPreviousQueryResults(QueryData& results) const {
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

bool Query::isQueryNameInDatabase() const {
  auto names = Query::getStoredQueryNames();
  return std::find(names.begin(), names.end(), name_) != names.end();
}

static inline void saveQuery(const std::string& name,
                             const std::string& query) {
  setDatabaseValue(kQueries, "query." + name, query);
}

bool Query::isNewQuery() const {
  std::string query;
  getDatabaseValue(kQueries, "query." + name_, query);
  return (query != query_.query);
}

Status Query::addNewResults(const QueryData& qd,
                            const uint64_t epoch,
                            uint64_t& counter) const {
  DiffResults dr;
  return addNewResults(qd, epoch, counter, dr, false);
}

Status Query::addNewResults(const QueryData& current_qd,
                            const uint64_t current_epoch,
                            uint64_t& counter,
                            DiffResults& dr,
                            bool calculate_diff) const {
  // The current results are 'fresh' when not calculating a differential.
  bool fresh_results = !calculate_diff;
  bool new_query = false;
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
    new_query = true;
    LOG(INFO) << "Scheduled query has been updated: " + name_;
    saveQuery(name_, query_.query);
  }

  // Use a 'target' avoid copying the query data when serializing and saving.
  // If a differential is requested and needed the target remains the original
  // query data, otherwise the content is moved to the differential's added set.
  const auto* target_gd = &current_qd;
  bool update_db = true;
  if (!fresh_results && calculate_diff) {
    // Get the rows from the last run of this query name.
    QueryData previous_qd;
    auto status = getPreviousQueryResults(previous_qd);
    if (!status.ok()) {
      return status;
    }

    // Calculate the differential between previous and current query results.
    dr = diff(previous_qd, current_qd);
    update_db = (!dr.added.empty() || !dr.removed.empty());
  } else {
    dr.added = std::move(current_qd);
    target_gd = &dr.added;
  }

  counter = getQueryCounter(fresh_results || new_query);
  auto status =
      setDatabaseValue(kQueries, name_ + "counter", std::to_string(counter));
  if (!status.ok()) {
    return status;
  }

  if (update_db) {
    // Replace the "previous" query data with the current.
    std::string json;
    status = serializeQueryDataJSON(*target_gd, json);
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

Status serializeRow(const Row& r, pt::ptree& tree) {
  try {
    for (auto& i : r) {
      tree.put<std::string>(i.first, i.second);
    }
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}

Status serializeRowRJ(const Row& r, rj::Document& d) {
  try {
    for (auto& i : r) {
      d.AddMember(rj::Value(i.first.c_str(), d.GetAllocator()).Move(),
                  rj::Value(i.second.c_str(), d.GetAllocator()).Move(),
                  d.GetAllocator());
    }
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}

Status serializeRow(const Row& r, const ColumnNames& cols, pt::ptree& tree) {
  try {
    for (auto& c : cols) {
      tree.add<std::string>(c, r.at(c));
    }
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}

Status serializeRowRJ(const Row& r, const ColumnNames& cols, rj::Document& d) {
  try {
    for (auto& c : cols) {
      d.AddMember(rj::Value(c.c_str(), d.GetAllocator()).Move(),
                  rj::Value(r.at(c).c_str(), d.GetAllocator()).Move(),
                  d.GetAllocator());
    }
  } catch (const std::exception& e) {
    return Status(1, e.what());
  }
  return Status(0, "OK");
}

Status serializeRowJSON(const Row& r, std::string& json) {
  pt::ptree tree;
  auto status = serializeRow(r, tree);
  if (!status.ok()) {
    return status;
  }

  std::ostringstream output;
  try {
    pt::write_json(output, tree, false);
  } catch (const pt::json_parser::json_parser_error& e) {
    // The content could not be represented as JSON.
    return Status(1, e.what());
  }
  json = output.str();
  return Status(0, "OK");
}

Status serializeRowJSONRJ(const Row& r, std::string& json) {
  rj::Document d(rj::kObjectType);
  auto status = serializeRowRJ(r, d);
  if (!status.ok()) {
    return status;
  }

  rj::StringBuffer sb;
  rj::Writer<rj::StringBuffer> writer(sb);
  d.Accept(writer);
  json = sb.GetString();
  return Status(0, "OK");
}

Status deserializeRow(const pt::ptree& tree, Row& r) {
  for (const auto& i : tree) {
    if (i.first.length() > 0) {
      r[i.first] = i.second.data();
    }
  }
  return Status(0, "OK");
}

Status deserializeRowRJ(const rj::Value& v, Row& r) {
  if (!v.IsObject()) {
    return Status(1, "Row not an object");
  }
  for (const auto& i : v.GetObject()) {
    std::string name(i.name.GetString());
    std::string value(i.value.GetString());
    if (name.length() > 0) {
      r[name] = value;
    }
  }
  return Status(0, "OK");
}

Status deserializeRowJSON(const std::string& json, Row& r) {
  pt::ptree tree;
  try {
    std::stringstream input;
    input << json;
    pt::read_json(input, tree);
  } catch (const pt::json_parser::json_parser_error& e) {
    return Status(1, e.what());
  }
  return deserializeRow(tree, r);
}

Status deserializeRowJSONRJ(const std::string& json, Row& r) {
  rj::Document d;
  if (d.Parse(json.c_str()).HasParseError()) {
    return Status(1, "Error serializing JSON");
  }
  return deserializeRowRJ(d, r);
}

Status serializeQueryData(const QueryData& q, pt::ptree& tree) {
  for (const auto& r : q) {
    pt::ptree serialized;
    auto status = serializeRow(r, serialized);
    if (!status.ok()) {
      return status;
    }
    tree.push_back(std::make_pair("", serialized));
  }
  return Status(0, "OK");
}

Status serializeQueryData(const QueryData& q,
                          const ColumnNames& cols,
                          pt::ptree& tree) {
  for (const auto& r : q) {
    pt::ptree serialized;
    auto status = serializeRow(r, cols, serialized);
    if (!status.ok()) {
      return status;
    }
    tree.push_back(std::make_pair("", serialized));
  }
  return Status(0, "OK");
}

Status serializeQueryDataJSON(const QueryData& q, std::string& json) {
  pt::ptree tree;
  auto status = serializeQueryData(q, tree);
  if (!status.ok()) {
    return status;
  }

  std::ostringstream output;
  try {
    pt::write_json(output, tree, false);
  } catch (const pt::json_parser::json_parser_error& e) {
    // The content could not be represented as JSON.
    return Status(1, e.what());
  }
  json = output.str();
  return Status(0, "OK");
}

Status serializeQueryDataJSONRJ(const QueryData& q, std::string& json) {
  rj::Document d;
  d.SetArray();
  auto status = serializeQueryDataRJ(q, d);
  if (!status.ok()) {
    return status;
  }

  rj::StringBuffer sb;
  rj::Writer<rj::StringBuffer> writer(sb);
  d.Accept(writer);
  json = sb.GetString();
  return Status(0, "OK");
}

Status deserializeQueryData(const pt::ptree& tree, QueryData& qd) {
  for (const auto& i : tree) {
    Row r;
    auto status = deserializeRow(i.second, r);
    if (!status.ok()) {
      return status;
    }
    qd.push_back(r);
  }
  return Status(0, "OK");
}

Status deserializeQueryDataRJ(const rj::Value& v, QueryData& qd) {
  if (!v.IsArray()) {
    return Status(1, "Not an array");
  }
  for (const auto& i : v.GetArray()) {
    Row r;
    auto status = deserializeRowRJ(i, r);
    if (!status.ok()) {
      return status;
    }
    qd.push_back(r);
  }
  return Status(0, "OK");
}

Status deserializeQueryDataJSON(const std::string& json, QueryData& qd) {
  pt::ptree tree;
  try {
    std::stringstream input;
    input << json;
    pt::read_json(input, tree);
  } catch (const pt::json_parser::json_parser_error& e) {
    return Status(1, e.what());
  }
  return deserializeQueryData(tree, qd);
}

Status serializeDiffResults(const DiffResults& d, pt::ptree& tree) {
  // Serialize and add "removed" first.
  // A property tree is somewhat ordered, this provides a loose contract to
  // the logger plugins and their aggregations, allowing them to parse chunked
  // lines. Note that the chunking is opaque to the database functions.
  pt::ptree removed;
  auto status = serializeQueryData(d.removed, removed);
  if (!status.ok()) {
    return status;
  }
  tree.add_child("removed", removed);

  pt::ptree added;
  status = serializeQueryData(d.added, added);
  if (!status.ok()) {
    return status;
  }
  tree.add_child("added", added);
  return Status(0, "OK");
}

Status deserializeDiffResults(const pt::ptree& tree, DiffResults& dr) {
  if (tree.count("removed") > 0) {
    auto status = deserializeQueryData(tree.get_child("removed"), dr.removed);
    if (!status.ok()) {
      return status;
    }
  }

  if (tree.count("added") > 0) {
    auto status = deserializeQueryData(tree.get_child("added"), dr.added);
    if (!status.ok()) {
      return status;
    }
  }
  return Status(0, "OK");
}

Status serializeDiffResultsJSON(const DiffResults& d, std::string& json) {
  pt::ptree tree;
  auto status = serializeDiffResults(d, tree);
  if (!status.ok()) {
    return status;
  }

  std::ostringstream output;
  try {
    pt::write_json(output, tree, false);
  } catch (const pt::json_parser::json_parser_error& e) {
    // The content could not be represented as JSON.
    return Status(1, e.what());
  }
  json = output.str();
  return Status(0, "OK");
}

DiffResults diff(const QueryData& old, const QueryData& current) {
  DiffResults r;
  QueryData overlap;

  for (const auto& i : current) {
    auto item = std::find(old.begin(), old.end(), i);
    if (item != old.end()) {
      overlap.push_back(i);
    } else {
      r.added.push_back(i);
    }
  }

  std::multiset<Row> overlap_set(overlap.begin(), overlap.end());
  std::multiset<Row> old_set(old.begin(), old.end());
  std::set_difference(old_set.begin(),
                      old_set.end(),
                      overlap_set.begin(),
                      overlap_set.end(),
                      std::back_inserter(r.removed));
  return r;
}

inline void addLegacyFieldsAndDecorations(const QueryLogItem& item,
                                          pt::ptree& tree) {
  // Apply legacy fields.
  tree.put<std::string>("name", item.name);
  tree.put<std::string>("hostIdentifier", item.identifier);
  tree.put<std::string>("calendarTime", item.calendar_time);
  tree.put<size_t>("unixTime", item.time);
  tree.put<uint64_t>("epoch", item.epoch);
  tree.put<uint64_t>("counter", item.counter);

  // Append the decorations.
  if (item.decorations.size() > 0) {
    auto decorator_parent = std::ref(tree);
    if (!FLAGS_decorations_top_level) {
      tree.add_child("decorations", pt::ptree());
      decorator_parent = tree.get_child("decorations");
    }
    for (const auto& name : item.decorations) {
      decorator_parent.get().put<std::string>(name.first, name.second);
    }
  }
}

inline void getLegacyFieldsAndDecorations(const pt::ptree& tree,
                                          QueryLogItem& item) {
  if (tree.count("decorations") > 0) {
    auto& decorations = tree.get_child("decorations");
    for (const auto& name : decorations) {
      item.decorations[name.first] = name.second.data();
    }
  }

  item.name = tree.get<std::string>("name", "");
  item.identifier = tree.get<std::string>("hostIdentifier", "");
  item.calendar_time = tree.get<std::string>("calendarTime", "");
  item.time = tree.get<int>("unixTime", 0);
}

Status serializeQueryLogItem(const QueryLogItem& item, pt::ptree& tree) {
  pt::ptree results_tree;
  if (item.results.added.size() > 0 || item.results.removed.size() > 0) {
    auto status = serializeDiffResults(item.results, results_tree);
    if (!status.ok()) {
      return status;
    }
    tree.add_child("diffResults", results_tree);
  } else {
    auto status = serializeQueryData(item.snapshot_results, results_tree);
    if (!status.ok()) {
      return status;
    }
    tree.add_child("snapshot", results_tree);
    tree.put<std::string>("action", "snapshot");
  }

  addLegacyFieldsAndDecorations(item, tree);
  return Status(0, "OK");
}

Status serializeQueryLogItemJSON(const QueryLogItem& i, std::string& json) {
  pt::ptree tree;
  auto status = serializeQueryLogItem(i, tree);
  if (!status.ok()) {
    return status;
  }

  std::ostringstream output;
  try {
    pt::write_json(output, tree, false);
  } catch (const pt::json_parser::json_parser_error& e) {
    // The content could not be represented as JSON.
    return Status(1, e.what());
  }
  json = output.str();
  return Status(0, "OK");
}

Status deserializeQueryLogItem(const pt::ptree& tree, QueryLogItem& item) {
  if (tree.count("diffResults") > 0) {
    auto status =
        deserializeDiffResults(tree.get_child("diffResults"), item.results);
    if (!status.ok()) {
      return status;
    }
  } else if (tree.count("snapshot") > 0) {
    auto status =
        deserializeQueryData(tree.get_child("snapshot"), item.snapshot_results);
    if (!status.ok()) {
      return status;
    }
  }

  getLegacyFieldsAndDecorations(tree, item);
  return Status(0, "OK");
}

Status deserializeQueryLogItemJSON(const std::string& json,
                                   QueryLogItem& item) {
  pt::ptree tree;
  try {
    std::stringstream input;
    input << json;
    pt::read_json(input, tree);
  } catch (const pt::json_parser::json_parser_error& e) {
    return Status(1, e.what());
  }
  return deserializeQueryLogItem(tree, item);
}

Status serializeEvent(const QueryLogItem& item,
                      const pt::ptree& event,
                      pt::ptree& tree) {
  addLegacyFieldsAndDecorations(item, tree);
  pt::ptree columns;
  for (auto& i : event) {
    // Yield results as a "columns." map to avoid namespace collisions.
    columns.put<std::string>(i.first, i.second.get_value<std::string>());
  }

  tree.add_child("columns", columns);
  return Status(0, "OK");
}

Status serializeQueryLogItemAsEvents(const QueryLogItem& i, pt::ptree& tree) {
  pt::ptree diff_results;
  // Note, snapshot query results will bypass the "AsEvents" call, even when
  // log_result_events is set. This is because the schedule will call an
  // explicit ::logSnapshotQuery, which does not check for the result_events
  // configuration.
  auto status = serializeDiffResults(i.results, diff_results);
  if (!status.ok()) {
    return status;
  }

  for (auto& action : diff_results) {
    for (auto& row : action.second) {
      pt::ptree event;
      serializeEvent(i, row.second, event);
      event.put<std::string>("action", action.first);
      tree.push_back(std::make_pair("", event));
    }
  }
  return Status(0, "OK");
}

Status serializeQueryLogItemAsEventsJSON(const QueryLogItem& i,
                                         std::vector<std::string>& items) {
  pt::ptree tree;
  auto status = serializeQueryLogItemAsEvents(i, tree);
  if (!status.ok()) {
    return status;
  }

  for (auto& event : tree) {
    std::ostringstream output;
    try {
      pt::write_json(output, event.second, false);
    } catch (const pt::json_parser::json_parser_error& e) {
      return Status(1, e.what());
    }
    items.push_back(output.str());
  }
  return Status(0, "OK");
}

Status serializeQueryDataRJ(const QueryData& q, rj::Document& d) {
  if (!d.IsArray()) {
    return Status(1, "Document is not an array");
  }
  for (const auto& r : q) {
    rj::Document serialized;
    serialized.SetObject();
    auto status = serializeRowRJ(r, serialized);
    if (!status.ok()) {
      return status;
    }
    if (serialized.GetObject().MemberCount()) {
      d.PushBack(rj::Value(serialized, d.GetAllocator()).Move(),
                 d.GetAllocator());
    }
  }
  return Status(0, "OK");
}

Status serializeQueryDataRJ(const QueryData& q,
                            const ColumnNames& cols,
                            rj::Document& d) {
  for (const auto& r : q) {
    rj::Document serialized;
    serialized.SetObject();
    auto status = serializeRowRJ(r, cols, serialized);
    if (!status.ok()) {
      return status;
    }
    if (serialized.GetObject().MemberCount()) {
      d.PushBack(rj::Value(serialized, d.GetAllocator()).Move(),
                 d.GetAllocator());
    }
  }
  return Status(0, "OK");
}

Status serializeDiffResultsRJ(const DiffResults& d, rj::Document& doc) {
  // Serialize and add "removed" first.
  // A property tree is somewhat ordered, this provides a loose contract to
  // the logger plugins and their aggregations, allowing them to parse chunked
  // lines. Note that the chunking is opaque to the database functions.
  rj::Document removed;
  auto status = serializeQueryDataRJ(d.removed, removed);
  if (!status.ok()) {
    return status;
  }

  doc.AddMember(rj::Value("removed", doc.GetAllocator()).Move(),
                rj::Value(removed, doc.GetAllocator()).Move(),
                doc.GetAllocator());

  rj::Document added;
  status = serializeQueryDataRJ(d.added, added);
  if (!status.ok()) {
    return status;
  }
  doc.AddMember(rj::Value("added", doc.GetAllocator()).Move(),
                rj::Value(added, doc.GetAllocator()).Move(),
                doc.GetAllocator());
  return Status(0, "OK");
}

bool addUniqueRowToQueryData(QueryData& q, const Row& r) {
  if (std::find(q.begin(), q.end(), r) != q.end()) {
    return false;
  }
  q.push_back(r);
  return true;
}
}
