/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <set>

#include <boost/lexical_cast.hpp>

#include <osquery/database.h>
#include <osquery/logger.h>

#include "osquery/core/json.h"

namespace pt = boost::property_tree;
namespace rj = rapidjson;

namespace osquery {

/// Generate a specific-use registry for database access abstraction.
CREATE_REGISTRY(DatabasePlugin, "database");

CLI_FLAG(bool, database_dump, false, "Dump the contents of the backing store");

CLI_FLAG(string,
         database_path,
         OSQUERY_DB_HOME "/osquery.db",
         "If using a disk-based backing store, specify a path");
FLAG_ALIAS(std::string, db_path, database_path);

FLAG(bool, disable_database, false, "Disable the persistent RocksDB storage");

DECLARE_bool(decorations_top_level);

const std::string kInternalDatabase = "rocksdb";
const std::string kPersistentSettings = "configurations";
const std::string kQueries = "queries";
const std::string kEvents = "events";
const std::string kCarves = "carves";
const std::string kLogs = "logs";

const std::vector<std::string> kDomains = {
    kPersistentSettings, kQueries, kEvents, kLogs, kCarves};

std::atomic<bool> DatabasePlugin::kDBAllowOpen(false);
std::atomic<bool> DatabasePlugin::kDBRequireWrite(false);
std::atomic<bool> DatabasePlugin::kDBInitialized(false);
std::atomic<bool> DatabasePlugin::kDBChecking(false);

/**
 * @brief A reader/writer mutex protecting database resets.
 *
 * A write is locked while using reset flows. A read is locked when calling
 * database plugin APIs.
 */
Mutex kDatabaseReset;

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

bool addUniqueRowToQueryData(QueryData& q, const Row& r) {
  if (std::find(q.begin(), q.end(), r) != q.end()) {
    return false;
  }
  q.push_back(r);
  return true;
}

Status DatabasePlugin::initPlugin() {
  // Initialize the database plugin using the flag.
  auto plugin = (FLAGS_disable_database) ? "ephemeral" : kInternalDatabase;
  auto status = RegistryFactory::get().setActive("database", plugin);
  if (!status.ok()) {
    // If the database did not setUp override the active plugin.
    RegistryFactory::get().setActive("database", "ephemeral");
  }

  kDBInitialized = true;
  return status;
}

void DatabasePlugin::shutdown() {
  auto datbase_registry = RegistryFactory::get().registry("database");
  for (auto& plugin : RegistryFactory::get().names("database")) {
    datbase_registry->remove(plugin);
  }
}

Status DatabasePlugin::reset() {
  // Keep this simple, scope the critical section to the broader methods.
  tearDown();
  return setUp();
}

bool DatabasePlugin::checkDB() {
  kDBChecking = true;
  bool result = true;
  try {
    auto status = setUp();
    if (kDBRequireWrite && read_only_) {
      result = false;
    }
    tearDown();
    result = status.ok();
  } catch (const std::exception& e) {
    VLOG(1) << "Database plugin check failed: " << e.what();
    result = false;
  }
  kDBChecking = false;
  return result;
}

Status DatabasePlugin::call(const PluginRequest& request,
                            PluginResponse& response) {
  if (request.count("action") == 0) {
    return Status(1, "Database plugin must include a request action");
  }

  // Get a domain/key, which are used for most database plugin actions.
  auto domain = (request.count("domain") > 0) ? request.at("domain") : "";
  auto key = (request.count("key") > 0) ? request.at("key") : "";

  if (request.at("action") == "reset") {
    WriteLock lock(kDatabaseReset);
    DatabasePlugin::kDBInitialized = false;
    // Prevent RocksDB reentrancy by logger plugins during plugin setup.
    VLOG(1) << "Resetting the database plugin: " << getName();
    auto status = this->reset();
    if (!status.ok()) {
      // The active database could not be reset, fallback to an ephemeral.
      Registry::get().setActive("database", "ephemeral");
      LOG(WARNING) << "Unable to reset database plugin: " << getName();
    }
    DatabasePlugin::kDBInitialized = true;
    return status;
  }

  // Switch over the possible database plugin actions.
  ReadLock lock(kDatabaseReset);
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
  } else if (request.at("action") == "remove_range") {
    auto key_high = (request.count("high") > 0) ? request.at("key_high") : "";
    if (!key_high.empty() && !key.empty()) {
      return this->removeRange(domain, key, key_high);
    }
    return Status(1, "Missing range");
  } else if (request.at("action") == "scan") {
    // Accumulate scanned keys into a vector.
    std::vector<std::string> keys;
    // Optionally allow the caller to request a max number of keys.
    size_t max = 0;
    if (request.count("max") > 0) {
      max = std::stoul(request.at("max"));
    }
    auto status = this->scan(domain, keys, request.at("prefix"), max);
    for (const auto& k : keys) {
      response.push_back({{"k", k}});
    }
    return status;
  }

  return Status(1, "Unknown database plugin action");
}

static inline std::shared_ptr<DatabasePlugin> getDatabasePlugin() {
  auto& rf = RegistryFactory::get();
  if (!rf.exists("database", rf.getActive("database"), true)) {
    return nullptr;
  }

  auto plugin = rf.plugin("database", rf.getActive("database"));
  return std::dynamic_pointer_cast<DatabasePlugin>(plugin);
}

Status getDatabaseValue(const std::string& domain,
                        const std::string& key,
                        std::string& value) {
  if (domain.empty()) {
    return Status(1, "Missing domain");
  }

  if (RegistryFactory::get().external()) {
    // External registries (extensions) do not have databases active.
    // It is not possible to use an extension-based database.
    PluginRequest request = {
        {"action", "get"}, {"domain", domain}, {"key", key}};
    PluginResponse response;
    auto status = Registry::call("database", request, response);
    if (status.ok()) {
      // Set value from the internally-known "v" key.
      if (response.size() > 0 && response[0].count("v") > 0) {
        value = response[0].at("v");
      }
    }
    return status;
  }

  ReadLock lock(kDatabaseReset);
  if (!DatabasePlugin::kDBInitialized) {
    throw std::runtime_error("Cannot get database value: " + key);
  } else {
    auto plugin = getDatabasePlugin();
    return plugin->get(domain, key, value);
  }
}

Status setDatabaseValue(const std::string& domain,
                        const std::string& key,
                        const std::string& value) {
  if (domain.empty()) {
    return Status(1, "Missing domain");
  }

  if (RegistryFactory::get().external()) {
    // External registries (extensions) do not have databases active.
    // It is not possible to use an extension-based database.
    PluginRequest request = {
        {"action", "put"}, {"domain", domain}, {"key", key}, {"value", value}};
    return Registry::call("database", request);
  }

  ReadLock lock(kDatabaseReset);
  if (!DatabasePlugin::kDBInitialized) {
    throw std::runtime_error("Cannot set database value: " + key);
  } else {
    auto plugin = getDatabasePlugin();
    return plugin->put(domain, key, value);
  }
}

Status deleteDatabaseValue(const std::string& domain, const std::string& key) {
  if (domain.empty()) {
    return Status(1, "Missing domain");
  }

  if (RegistryFactory::get().external()) {
    // External registries (extensions) do not have databases active.
    // It is not possible to use an extension-based database.
    PluginRequest request = {
        {"action", "remove"}, {"domain", domain}, {"key", key}};
    return Registry::call("database", request);
  }

  ReadLock lock(kDatabaseReset);
  if (!DatabasePlugin::kDBInitialized) {
    throw std::runtime_error("Cannot delete database value: " + key);
  } else {
    auto plugin = getDatabasePlugin();
    return plugin->remove(domain, key);
  }
}

Status deleteDatabaseRange(const std::string& domain,
                           const std::string& low,
                           const std::string& high) {
  if (domain.empty()) {
    return Status(1, "Missing domain");
  }

  if (RegistryFactory::get().external()) {
    // External registries (extensions) do not have databases active.
    // It is not possible to use an extension-based database.
    PluginRequest request = {{"action", "remove_range"},
                             {"domain", domain},
                             {"key", low},
                             {"key_high", high}};
    return Registry::call("database", request);
  }

  ReadLock lock(kDatabaseReset);
  if (!DatabasePlugin::kDBInitialized) {
    throw std::runtime_error("Cannot delete database values: " + low + " - " +
                             high);
  } else {
    auto plugin = getDatabasePlugin();
    return plugin->removeRange(domain, low, high);
  }
}

Status scanDatabaseKeys(const std::string& domain,
                        std::vector<std::string>& keys,
                        size_t max) {
  return scanDatabaseKeys(domain, keys, "", max);
}

/// Get a list of keys for a given domain.
Status scanDatabaseKeys(const std::string& domain,
                        std::vector<std::string>& keys,
                        const std::string& prefix,
                        size_t max) {
  if (domain.empty()) {
    return Status(1, "Missing domain");
  }

  if (RegistryFactory::get().external()) {
    // External registries (extensions) do not have databases active.
    // It is not possible to use an extension-based database.
    PluginRequest request = {{"action", "scan"},
                             {"domain", domain},
                             {"prefix", prefix},
                             {"max", std::to_string(max)}};
    PluginResponse response;
    auto status = Registry::call("database", request, response);

    for (const auto& item : response) {
      if (item.count("k") > 0) {
        keys.push_back(item.at("k"));
      }
    }
    return status;
  }

  ReadLock lock(kDatabaseReset);
  if (!DatabasePlugin::kDBInitialized) {
    throw std::runtime_error("Cannot scan database values: " + prefix);
  } else {
    auto plugin = getDatabasePlugin();
    return plugin->scan(domain, keys, prefix, max);
  }
}

void resetDatabase() {
  PluginRequest request = {{"action", "reset"}};
  Registry::call("database", request);
}

void dumpDatabase() {
  for (const auto& domain : kDomains) {
    std::vector<std::string> keys;
    if (!scanDatabaseKeys(domain, keys)) {
      continue;
    }
    for (const auto& key : keys) {
      std::string value;
      if (!getDatabaseValue(domain, key, value)) {
        continue;
      }
      fprintf(
          stdout, "%s[%s]: %s\n", domain.c_str(), key.c_str(), value.c_str());
    }
  }
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
}
