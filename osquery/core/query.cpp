/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <algorithm>
#include <random>
#include <string>
#include <type_traits>
#include <vector>

#include <osquery/core/flagalias.h>
#include <osquery/core/flags.h>
#include <osquery/core/query.h>
#include <osquery/database/database.h>
#include <osquery/logger/logger.h>

#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/siphash.h>

namespace rj = rapidjson;

namespace osquery {

DECLARE_bool(decorations_top_level);

/// Log numeric values as numbers (in JSON syntax)
FLAG(bool,
     logger_numerics,
     false,
     "Use numeric JSON syntax for numeric values");
FLAG_ALIAS(bool, log_numerics_as_numbers, logger_numerics);

namespace {

/// Random 128-bit key of the result hash, generated once per installation and
/// kept in the database, which is readable by root only. Differential results
/// are a detection mechanism: without the key, an attacker able to control
/// table contents could craft a result set colliding with the stored hash to
/// hide rows from the 'added'/'removed' results.
std::pair<uint64_t, uint64_t> queryHashKey() {
  static std::pair<uint64_t, uint64_t> key =
      []() -> std::pair<uint64_t, uint64_t> {
    std::string raw;
    if (getDatabaseValue(kPersistentSettings, "diff_hash_key", raw).ok()) {
      auto separator = raw.find(' ');
      if (separator != std::string::npos) {
        auto key0 = tryTo<uint64_t>(raw.substr(0, separator));
        auto key1 = tryTo<uint64_t>(raw.substr(separator + 1));
        if (key0 && key1) {
          return {key0.take(), key1.take()};
        }
      }
    }
    // A missing or corrupt value falls through and regenerates the key.
    std::random_device rd;
    auto half = [&rd]() -> uint64_t {
      return (static_cast<uint64_t>(rd()) << 32) | static_cast<uint64_t>(rd());
    };
    uint64_t key0 = half();
    uint64_t key1 = half();
    setDatabaseValue(kPersistentSettings,
                     "diff_hash_key",
                     std::to_string(key0) + " " + std::to_string(key1));
    return {key0, key1};
  }();
  return key;
}

/// Absorb a 64-bit value in little endian order, independent of the host
/// byte order.
void updateU64LE(SipHash24& hash, uint64_t value) {
  unsigned char bytes[8];
  for (size_t i = 0; i < sizeof(bytes); ++i) {
    bytes[i] = static_cast<unsigned char>(value >> (8 * i));
  }
  hash.update(bytes, sizeof(bytes));
}

/// SipHash-2-4 of a single row, independent of the column order (rows are
/// maps). Each column name and string value is length prefixed, so adjacent
/// strings cannot be regrouped into different columns with the same byte
/// stream, and the variant index is hashed too, so the same bytes cannot hash
/// the same under a different value type. Allocates nothing.
uint64_t hashRow(const RowTyped& row, uint64_t key0, uint64_t key1) {
  SipHash24 hash(key0, key1);
  for (const auto& column : row) {
    updateU64LE(hash, column.first.size());
    hash.update(column.first.data(), column.first.size());
    updateU64LE(hash, column.second.which());
    boost::apply_visitor(
        [&](const auto& value) {
          using T = std::decay_t<decltype(value)>;
          if constexpr (std::is_same_v<T, std::string>) {
            updateU64LE(hash, value.size());
            hash.update(value.data(), value.size());
          } else {
            hash.update(&value, sizeof(T));
          }
        },
        column.second);
  }
  return hash.digest();
}

/// SipHash-2-4 of a result set with the same semantics as diff(): only the
/// multiset of rows matters, not their order. Combining the sorted per-row
/// hashes keeps duplicate rows counted while removing the order.
uint64_t hashQueryData(const QueryDataTyped& qd) {
  auto [key0, key1] = queryHashKey();
  std::vector<uint64_t> row_hashes;
  row_hashes.reserve(qd.size());
  for (const auto& row : qd) {
    row_hashes.push_back(hashRow(row, key0, key1));
  }
  std::sort(row_hashes.begin(), row_hashes.end());
  SipHash24 hash(key0, key1);
  for (const auto& row_hash : row_hashes) {
    updateU64LE(hash, row_hash);
  }
  return hash.digest();
}

} // namespace

uint64_t Query::getPreviousEpoch() const {
  uint64_t epoch = 0;
  std::string raw;
  auto status = getDatabaseValue(kQueries, name_ + "epoch", raw);
  if (status.ok()) {
    epoch = std::stoull(raw);
  }
  return epoch;
}

uint64_t Query::getQueryCounter(bool is_reset,
                                bool reset_has_all_records) const {
  uint64_t counter = 0;
  if (is_reset) {
    if (reset_has_all_records) {
      return counter;
    } else {
      // If it's a reset but not returning all records, start with 1 instead of
      // 0. This allows consumers to reliably distinguish between differential
      // results and results with all records.
      return counter + 1;
    }
  }

  std::string raw;
  auto status = getDatabaseValue(kQueries, name_ + "counter", raw);
  if (status.ok()) {
    counter = std::stoull(raw) + 1;
  }
  return counter;
}

Status Query::getPreviousQueryResults(QueryDataSet& results) const {
  std::string raw;
  auto status = getDatabaseValue(kQueries, name_, raw);
  if (!status.ok()) {
    return status;
  }

  status = deserializeQueryDataJSON(raw, results);
  if (!status.ok()) {
    return status;
  }
  return Status::success();
}

Status Query::saveQueryResults(const std::string& json,
                               uint64_t epoch,
                               const std::string& hash) const {
  // The hash is stored after the epoch in the same value ("<epoch> <hash>"),
  // so the results and the hash describing them are always written together,
  // and no part of the query name space needs to be reserved for it. Reading
  // the epoch with stoull stops at the space, and an osquery version without
  // this support rewriting the epoch drops the hash, invalidating it after a
  // downgrade and re-upgrade.
  DatabaseStringValueList data;
  data.push_back({name_, json});
  data.push_back({name_ + "epoch", std::to_string(epoch) + " " + hash});
  return setDatabaseBatch(kQueries, data);
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

bool Query::isNewQuerySql() const {
  std::string query;
  getDatabaseValue(kQueries, "query." + name_, query);
  return (query != query_);
}

void Query::getQueryStatus(uint64_t epoch,
                           bool& new_query_epoch,
                           bool& new_query_sql) const {
  if (!isQueryNameInDatabase()) {
    // This is the first encounter of the scheduled query.
    new_query_epoch = true;
    new_query_sql = true;
    LOG(INFO) << "Storing initial results for new scheduled query: " << name_;
    saveQuery(name_, query_);
  } else if (getPreviousEpoch() != epoch) {
    new_query_epoch = true;
    LOG(INFO) << "New Epoch " << epoch << " for scheduled query " << name_;
  } else if (isNewQuerySql()) {
    // This query sql is 'new' indicating that the previous results may be
    // invalid.
    new_query_sql = true;
    LOG(INFO) << "Scheduled query has been updated: " + name_;
    saveQuery(name_, query_);
  }
}

Status Query::incrementCounter(bool is_reset,
                               bool reset_has_all_records,
                               uint64_t& counter) const {
  counter = getQueryCounter(is_reset, reset_has_all_records);
  return setDatabaseValue(kQueries, name_ + "counter", std::to_string(counter));
}

Status Query::addNewEvents(QueryDataTyped current_qd,
                           const uint64_t current_epoch,
                           uint64_t& counter,
                           DiffResults& dr) const {
  bool new_query_epoch = false;
  bool new_query_sql = false;
  getQueryStatus(current_epoch, new_query_epoch, new_query_sql);
  if (new_query_epoch) {
    // Store the hash of the empty result set together with the results, so
    // the stored hash keeps describing the stored results.
    auto status = saveQueryResults(
        "[]", current_epoch, std::to_string(hashQueryData(QueryDataTyped{})));
    if (!status.ok()) {
      return status;
    }
  }
  dr.added = std::move(current_qd);
  if (!dr.added.empty()) {
    auto status = incrementCounter(new_query_epoch, false, counter);
    if (!status.ok()) {
      return status;
    }
  }
  return Status::success();
}

Status Query::addNewResults(QueryDataTyped current_qd,
                            const uint64_t current_epoch,
                            uint64_t& counter,
                            DiffResults& dr) const {
  bool new_query_epoch = false;
  bool new_query_sql = false;
  getQueryStatus(current_epoch, new_query_epoch, new_query_sql);

  // Use a 'target' avoid copying the query data when serializing and saving.
  // If a differential is requested and needed the target remains the original
  // query data, otherwise the content is moved to the differential's added set.
  const auto* target_gd = &current_qd;
  bool update_db = true;
  // Whether the stored hash already describes the current rows.
  bool hash_matched = false;
  // Hash of the current rows; the stored results always end up equal to them,
  // so it is saved alongside them to let the next run skip the differential.
  auto current_hash = hashQueryData(current_qd);
  if (!new_query_epoch) {
    // The hash is stored after the epoch in the same value. An epoch value
    // without a hash (or a missing epoch) simply falls back to the full
    // differential.
    std::string stored_epoch;
    getDatabaseValue(kQueries, name_ + "epoch", stored_epoch);
    std::string stored_hash;
    auto separator = stored_epoch.find(' ');
    if (separator != std::string::npos) {
      stored_hash = stored_epoch.substr(separator + 1);
    }
    hash_matched = stored_hash == std::to_string(current_hash);
    if (hash_matched) {
      // The results are identical to the last run: the differential is empty
      // and the stored results can stay in the database unparsed. The output
      // differential is reset, as the caller may reuse it across runs.
      dr.added.clear();
      dr.removed.clear();
      update_db = false;
    } else {
      // Get the rows from the last run of this query name.
      QueryDataSet previous_qd;
      auto status = getPreviousQueryResults(previous_qd);
      if (!status.ok()) {
        return status;
      }

      // Calculate the differential between previous and current query results.
      dr = diff(previous_qd, current_qd);

      update_db = (!dr.added.empty() || !dr.removed.empty());
    }
  } else {
    dr.added = std::move(current_qd);
    target_gd = &dr.added;
  }

  if (update_db) {
    // Replace the "previous" query data with the current.
    std::string json;
    auto status = serializeQueryDataJSON(*target_gd, json, true);
    if (!status.ok()) {
      return status;
    }

    status =
        saveQueryResults(json, current_epoch, std::to_string(current_hash));
    if (!status.ok()) {
      return status;
    }
  } else if (!new_query_epoch && !hash_matched) {
    // The differential ran and came back empty, and the stored hash was
    // missing or described different results: remember the hash of the
    // unchanged results so the next run can skip them. A matching hash writes
    // nothing at all.
    auto status = setDatabaseValue(
        kQueries,
        name_ + "epoch",
        std::to_string(current_epoch) + " " + std::to_string(current_hash));
    if (!status.ok()) {
      return status;
    }
  }

  if (update_db || new_query_epoch) {
    auto status = incrementCounter(new_query_epoch, true, counter);
    if (!status.ok()) {
      return status;
    }
  }
  return Status::success();
}

Status deserializeDiffResults(const rj::Value& doc, DiffResults& dr) {
  if (!doc.IsObject()) {
    return Status(1);
  }

  if (doc.HasMember("removed")) {
    auto status = deserializeQueryData(doc["removed"], dr.removed);
    if (!status.ok()) {
      return status;
    }
  }

  if (doc.HasMember("added")) {
    auto status = deserializeQueryData(doc["added"], dr.added);
    if (!status.ok()) {
      return status;
    }
  }
  return Status::success();
}

inline void addLegacyFieldsAndDecorations(const QueryLogItem& item,
                                          JSON& doc,
                                          rj::Document& obj) {
  // Apply legacy fields.
  doc.addRef("name", item.name, obj);
  doc.addRef("hostIdentifier", item.identifier, obj);
  doc.addRef("calendarTime", item.calendar_time, obj);
  doc.addCopy("unixTime", item.time, obj);
  doc.addCopy("epoch", static_cast<size_t>(item.epoch), obj);
  doc.addCopy("counter", static_cast<size_t>(item.counter), obj);

  // Apply field indicating if numerics are serialized as numbers
  doc.addCopy("numerics", FLAGS_logger_numerics, obj);

  // Append the decorations.
  if (!item.decorations.empty()) {
    auto dec_obj = doc.getObject();
    auto target_obj = std::ref(dec_obj);
    if (FLAGS_decorations_top_level) {
      target_obj = std::ref(obj);
    }
    for (const auto& name : item.decorations) {
      doc.addRef(name.first, name.second, target_obj);
    }
    if (!FLAGS_decorations_top_level) {
      doc.addCopy("decorations", dec_obj, obj);
    }
  }
}

inline void getLegacyFieldsAndDecorations(const JSON& doc, QueryLogItem& item) {
  if (doc.doc().HasMember("decorations")) {
    if (doc.doc()["decorations"].IsObject()) {
      for (const auto& i : doc.doc()["decorations"].GetObject()) {
        item.decorations[i.name.GetString()] = i.value.GetString();
      }
    }
  }

  item.name = doc.doc()["name"].GetString();
  item.identifier = doc.doc()["hostIdentifier"].GetString();
  item.calendar_time = doc.doc()["calendarTime"].GetString();
  item.time = doc.doc()["unixTime"].GetUint64();
}

Status serializeQueryLogItem(const QueryLogItem& item, JSON& doc) {
  if (!item.isSnapshot) {
    auto obj = doc.getObject();
    auto status =
        serializeDiffResults(item.results, doc, obj, FLAGS_logger_numerics);
    if (!status.ok()) {
      return status;
    }

    doc.addCopy("diffResults", obj);
  } else {
    auto arr = doc.getArray();
    auto status = serializeQueryData(
        item.snapshot_results, doc, arr, FLAGS_logger_numerics);
    if (!status.ok()) {
      return status;
    }

    doc.addCopy("snapshot", arr);
    doc.addRef("action", "snapshot");
  }

  addLegacyFieldsAndDecorations(item, doc, doc.doc());
  return Status::success();
}

Status serializeEvent(const QueryLogItem& item,
                      const rj::Value& event_obj,
                      JSON& doc,
                      rj::Document& obj) {
  addLegacyFieldsAndDecorations(item, doc, obj);
  auto columns_obj = doc.getObject();
  for (const auto& i : event_obj.GetObject()) {
    // Yield results as a "columns." map to avoid namespace collisions.
    doc.addCopy(i.name.GetString(), i.value, columns_obj);
  }
  doc.addCopy("columns", columns_obj, obj);
  return Status::success();
}

Status serializeQueryLogItemAsEvents(const QueryLogItem& item, JSON& doc) {
  auto temp_doc = JSON::newObject();
  if (!item.isSnapshot) {
    if (!item.results.hasNoResults()) {
      auto status = serializeDiffResults(
          item.results, temp_doc, temp_doc.doc(), FLAGS_logger_numerics);
      if (!status.ok()) {
        return status;
      }
    } else {
      return Status::success();
    }
  } else {
    if (!item.snapshot_results.empty()) {
      auto arr = doc.getArray();
      auto status = serializeQueryData(
          item.snapshot_results, temp_doc, arr, FLAGS_logger_numerics);
      if (!status.ok()) {
        return status;
      }
      temp_doc.addCopy("snapshot", arr);
    } else {
      return Status::success();
    }
  }

  for (auto& action : temp_doc.doc().GetObject()) {
    for (auto& row : action.value.GetArray()) {
      auto obj = doc.getObject();
      serializeEvent(item, row, doc, obj);
      doc.addCopy("action", action.name.GetString(), obj);
      doc.pushCopy(obj);
    }
  }
  return Status::success();
}

Status serializeQueryLogItemJSON(const QueryLogItem& item, std::string& json) {
  auto doc = JSON::newObject();
  auto status = serializeQueryLogItem(item, doc);
  if (!status.ok()) {
    return status;
  }

  return doc.toString(json);
}

Status serializeQueryLogItemAsEventsJSON(const QueryLogItem& item,
                                         std::vector<std::string>& items) {
  auto doc = JSON::newArray();
  auto status = serializeQueryLogItemAsEvents(item, doc);
  if (!status.ok()) {
    return status;
  }

  // return doc.toString()
  for (auto& event : doc.doc().GetArray()) {
    rj::StringBuffer sb;
    rj::Writer<rj::StringBuffer> writer(sb);
    event.Accept(writer);
    items.push_back(sb.GetString());
  }
  return Status::success();
}

} // namespace osquery
