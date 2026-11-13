/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/eventsubscriber.h>

#include "mockedosquerydatabase.h"
#include "osquery/core/sql/row.h"

namespace osquery {

namespace {

const Row kBaseRow = {
    {"key1", "value1"},
    {"key2", "value2"},
    {"key3", "value3"},
    {"key4", "value4"},
};

} // namespace

extern const std::string kEvents;
extern const std::string kExecutingQuery;

void MockedOsqueryDatabase::generateEvents(const std::string& publisher,
                                           const std::string& name) {
  EventSubscriberPlugin::Context context;
  EventSubscriberPlugin::setDatabaseNamespace(context, publisher, name);

  auto row = kBaseRow;

  for (std::size_t i = 0U; i < 10U; ++i) {
    auto event_id = EventSubscriberPlugin::generateEventIdentifier(context);

    auto row = kBaseRow;
    row.insert({"time", std::to_string(i)});
    row.insert({"eid", std::to_string(event_id)});

    std::string serialized_row;
    auto status = serializeRowJSON(row, serialized_row);
    if (!status.ok()) {
      throw std::runtime_error(
          "MockedOsqueryDatabase: Failed to serialize the row");
    }

    auto key = EventSubscriberPlugin::databaseKeyForEventId(context, event_id);
    key_map.insert({key, std::move(serialized_row)});

    // this value can't be deserialized and should be skipped
    event_id = EventSubscriberPlugin::generateEventIdentifier(context);
    key = EventSubscriberPlugin::databaseKeyForEventId(context, event_id);
    key_map.insert({key, "broken_serialized_value"});
  }
}

Status MockedOsqueryDatabase::getDatabaseValue(const std::string& domain,
                                               const std::string& key,
                                               std::string& value) const {
  value = {};

  if (domain == kEvents) {
    auto key_it = key_map.find(key);
    if (key_it == key_map.end()) {
      throw std::logic_error(
          "MockedOsqueryDatabase: Invalid key passed to getDatabaseValue: " +
          key);
    }

    value = key_it->second;
    return Status::success();

  } else if (domain == kPersistentSettings) {
    if (key != kExecutingQuery) {
      throw std::logic_error(
          "MockedOsqueryDatabase: Invalid key passed to getDatabaseValue: " +
          key);
    }

    value = "test_query";
    return Status::success();

  } else {
    throw std::logic_error(
        "MockedOsqueryDatabase: Invalid domain passed to getDatabaseValue: " +
        domain);
  }
}

Status MockedOsqueryDatabase::getDatabaseValue(const std::string& domain,
                                               const std::string& key,
                                               int& value) const {
  return Status::failure(
      "MockedOsqueryDatabase: Unsupported getDatabaseValue call");
}

Status MockedOsqueryDatabase::setDatabaseValue(const std::string& domain,
                                               const std::string& key,
                                               const std::string& value) const {
  if (domain != kEvents) {
    throw std::logic_error(
        "MockedOsqueryDatabase: Invalid domain passed to setDatabaseValue: " +
        domain);
  }

  if (key != "optimize.test_query" && key != "optimize_eid.test_query") {
    throw std::logic_error(
        "MockedOsqueryDatabase: Invalid key passed to setDatabaseValue: " +
        key);
  }

  key_map[key] = value;
  return Status::success();
}

Status MockedOsqueryDatabase::setDatabaseValue(const std::string& domain,
                                               const std::string& key,
                                               int value) const {
  return Status::failure(
      "MockedOsqueryDatabase: Unsupported setDatabaseValue call");
}

Status MockedOsqueryDatabase::setDatabaseBatch(
    const std::string& domain, const DatabaseStringValueList& data) const {
  return Status::failure(
      "MockedOsqueryDatabase: Unsupported setDatabaseBatch call");
}

Status MockedOsqueryDatabase::deleteDatabaseValue(
    const std::string& domain, const std::string& key) const {
  if (domain != kEvents) {
    throw std::logic_error(
        "MockedOsqueryDatabase: Invalid domain passed to "
        "deleteDatabaseValue: " +
        domain);
  }

  auto key_it = key_map.find(key);
  if (key_it == key_map.end()) {
    throw std::logic_error(
        "MockedOsqueryDatabase: Invalid key passed to deleteDatabaseValue: " +
        key);
  }

  key_map.erase(key_it);
  return Status::success();
}

Status MockedOsqueryDatabase::deleteDatabaseRange(
    const std::string& domain,
    const std::string& low,
    const std::string& high) const {
  return Status::failure(
      "MockedOsqueryDatabase: Unsupported deleteDatabaseRange call");
}

Status MockedOsqueryDatabase::scanDatabaseKeys(const std::string& domain,
                                               std::vector<std::string>& keys,
                                               size_t max) const {
  return Status::failure(
      "MockedOsqueryDatabase: Unsupported scanDatabaseKeys call");
}

Status MockedOsqueryDatabase::scanDatabaseKeys(const std::string& domain,
                                               std::vector<std::string>& keys,
                                               const std::string& prefix,
                                               size_t max) const {
  keys = {};

  if (max != 0 || domain != kEvents) {
    throw std::logic_error(
        "MockedOsqueryDatabase: Invalid parameter passed to scanDatabaseKeys. "
        "max=" +
        std::to_string(max) + " domain:" + domain);
  }

  for (const auto& p : key_map) {
    const auto& current_key = p.first;

    if (current_key.find(prefix) == 0) {
      keys.push_back(current_key);
    }
  }

  return Status::success();
}

} // namespace osquery
