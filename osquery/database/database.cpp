/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <algorithm>
#include <iostream>
#include <sstream>
#include <set>
#include <string>
#include <vector>

#include <boost/lexical_cast.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/database.h>
#include <osquery/logger.h>

namespace pt = boost::property_tree;

namespace osquery {

typedef unsigned char byte;

/////////////////////////////////////////////////////////////////////////////
// Row - the representation of a row in a set of database results. Row is a
// simple map where individual column names are keys, which map to the Row's
// respective value
/////////////////////////////////////////////////////////////////////////////

std::string escapeNonPrintableBytes(const std::string& data) {
  std::string escaped;
  // clang-format off
  char const hex_chars[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'A', 'B', 'C', 'D', 'E', 'F',
  };
  // clang-format on
  for (int i = 0; i < data.length(); i++) {
    if (((byte)data[i]) < 0x20 || ((byte)data[i]) >= 0x80) {
      escaped += "\\x";
      escaped += hex_chars[(((byte)data[i])) >> 4];
      escaped += hex_chars[((byte)data[i] & 0x0F) >> 0];
    } else {
      escaped += data[i];
    }
  }
  return escaped;
}

void escapeQueryData(const QueryData& oldData, QueryData& newData) {
  for (const auto& r : oldData) {
    Row newRow;
    for (auto& i : r) {
      newRow[i.first] = escapeNonPrintableBytes(i.second);
    }
    newData.push_back(newRow);
  }
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

Status deserializeRow(const pt::ptree& tree, Row& r) {
  for (const auto& i : tree) {
    if (i.first.length() > 0) {
      r[i.first] = i.second.data();
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

/////////////////////////////////////////////////////////////////////////////
// QueryData - the representation of a database query result set. It's a
// vector of rows
/////////////////////////////////////////////////////////////////////////////

Status serializeQueryData(const QueryData& q, pt::ptree& tree) {
  for (const auto& r : q) {
    pt::ptree serialized;
    auto s = serializeRow(r, serialized);
    if (!s.ok()) {
      return s;
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

/////////////////////////////////////////////////////////////////////////////
// DiffResults - the representation of two diffed QueryData result sets.
// Given and old and new QueryData, DiffResults indicates the "added" subset
// of rows and the "removed" subset of Rows
/////////////////////////////////////////////////////////////////////////////

Status serializeDiffResults(const DiffResults& d, pt::ptree& tree) {
  pt::ptree added;
  auto status = serializeQueryData(d.added, added);
  if (!status.ok()) {
    return status;
  }
  tree.add_child("added", added);

  pt::ptree removed;
  status = serializeQueryData(d.removed, removed);
  if (!status.ok()) {
    return status;
  }
  tree.add_child("removed", removed);
  return Status(0, "OK");
}

Status deserializeDiffResults(const pt::ptree& tree, DiffResults& dr) {
  if (tree.count("added") > 0) {
    auto status = deserializeQueryData(tree.get_child("added"), dr.added);
    if (!status.ok()) {
      return status;
    }
  }

  if (tree.count("removed") > 0) {
    auto status = deserializeQueryData(tree.get_child("removed"), dr.removed);
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

/////////////////////////////////////////////////////////////////////////////
// QueryLogItem - the representation of a log result occuring when a
// scheduled query yields operating system state change.
/////////////////////////////////////////////////////////////////////////////

Status serializeQueryLogItem(const QueryLogItem& i, pt::ptree& tree) {
  pt::ptree results_tree;
  if (i.results.added.size() > 0 || i.results.removed.size() > 0) {
    auto status = serializeDiffResults(i.results, results_tree);
    if (!status.ok()) {
      return status;
    }
    tree.add_child("diffResults", results_tree);
  } else {
    auto status = serializeQueryData(i.snapshot_results, results_tree);
    if (!status.ok()) {
      return status;
    }
    tree.add_child("snapshot", results_tree);
  }

  tree.put<std::string>("name", i.name);
  tree.put<std::string>("hostIdentifier", i.identifier);
  tree.put<std::string>("calendarTime", i.calendar_time);
  tree.put<int>("unixTime", i.time);
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

  item.name = tree.get<std::string>("name", "");
  item.identifier = tree.get<std::string>("hostIdentifier", "");
  item.calendar_time = tree.get<std::string>("calendarTime", "");
  item.time = tree.get<int>("unixTime", 0);
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
  tree.put<std::string>("name", item.name);
  tree.put<std::string>("hostIdentifier", item.identifier);
  tree.put<std::string>("calendarTime", item.calendar_time);
  tree.put<int>("unixTime", item.time);

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
                                         std::string& json) {
  pt::ptree tree;
  auto status = serializeQueryLogItemAsEvents(i, tree);
  if (!status.ok()) {
    return status;
  }

  std::ostringstream output;
  for (auto& event : tree) {
    try {
      pt::write_json(output, event.second, false);
    } catch (const pt::json_parser::json_parser_error& e) {
      return Status(1, e.what());
    }
  }
  json = output.str();
  return Status(0, "OK");
}

bool addUniqueRowToQueryData(QueryData& q, const Row& r) {
  if (std::find(q.begin(), q.end(), r) != q.end()) {
    return false;
  }
  q.push_back(r);
  return true;
}

Status DatabasePlugin::call(const PluginRequest& request,
                            PluginResponse& response) {
  if (request.count("action") == 0) {
    return Status(1, "Database plugin must include a request action");
  }

  // Get a domain/key, which are used for most database plugin actions.
  auto domain = (request.count("domain") > 0) ? request.at("domain") : "";
  auto key = (request.count("key") > 0) ? request.at("key") : "";

  // Switch over the possible database plugin actions.
  if (request.at("action") == "get") {
    std::string value;
    auto status = this->get(domain, key, value);
    response.push_back({{"v", value}});
    return status;
  } else if (request.at("action") == "put") {
    if (request.count("value") == 0) {
      return Status(1, "Database plugin put action requires a value");
    }
    return this->put(domain, key, request.at("value"));
  } else if (request.at("action") == "remove") {
    return this->remove(domain, key);
  } else if (request.at("action") == "scan") {
    std::vector<std::string> keys;
    auto status = this->scan(domain, keys);
    for (const auto& key : keys) {
      response.push_back({{"k", key}});
    }
    return status;
  }

  return Status(1, "Unknown database plugin action");
}

Status getDatabaseValue(const std::string& domain,
                        const std::string& key,
                        std::string& value) {
  PluginRequest request = {{"action", "get"}, {"domain", domain}, {"key", key}};
  PluginResponse response;
  auto status = Registry::call("database", "rocks", request, response);
  if (!status.ok()) {
    VLOG(1) << "Cannot get database " << domain << "/" << key << ": "
            << status.getMessage();
    return status;
  }

  // Set value from the internally-known "v" key.
  if (response.size() > 0 && response[0].count("v") > 0) {
    value = response[0].at("v");
  }
  return status;
}

Status setDatabaseValue(const std::string& domain,
                        const std::string& key,
                        const std::string& value) {
  PluginRequest request = {
      {"action", "put"}, {"domain", domain}, {"key", key}, {"value", value}};
  return Registry::call("database", "rocks", request);
}

Status deleteDatabaseValue(const std::string& domain, const std::string& key) {
  PluginRequest request = {
      {"action", "remove"}, {"domain", domain}, {"key", key}};
  return Registry::call("database", "rocks", request);
}

Status scanDatabaseKeys(const std::string& domain,
                        std::vector<std::string>& keys) {
  PluginRequest request = {{"action", "scan"}, {"domain", domain}};
  PluginResponse response;
  auto status = Registry::call("database", "rocks", request, response);

  for (const auto& item : response) {
    if (item.count("k") > 0) {
      keys.push_back(item.at("k"));
    }
  }
  return status;
}
}
