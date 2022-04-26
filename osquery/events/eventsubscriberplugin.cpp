/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/config/config.h>
#include <osquery/core/flags.h>
#include <osquery/database/database.h>
#include <osquery/events/eventfactory.h>
#include <osquery/events/eventsubscriberplugin.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/info/tool_type.h>
#include <osquery/utils/system/time.h>

namespace osquery {

namespace {

/// Checkpoint interval to inspect max event buffering.
const EventContextID kEventsCheckpoint{256U};

void removeDeprecatedEventKeysOnceHelper() {
  std::vector<std::string> key_list;
  auto status = scanDatabaseKeys(kEvents, key_list);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to scan the database keys";
    return;
  }

  std::size_t error_count{};
  std::size_t deleted_key_count{};

  for (const auto& key : key_list) {
    auto erase_key = (key.find("eid.") == 0U) || (key.find("indexes.") == 0U) ||
                     (key.find("records.") == 0U);

    if (!erase_key) {
      continue;
    }

    status = deleteDatabaseValue(kEvents, key);
    if (status.ok()) {
      ++deleted_key_count;
    } else {
      ++error_count;
    }
  }

  if (error_count != 0U) {
    LOG(ERROR) << "One or more deprecated event keys could not be deleted";
  }

  if (deleted_key_count != 0U) {
    LOG(INFO) << "Removed " << deleted_key_count
              << " deprecated event keys from the database";
  }
}

void removeDeprecatedEventKeysOnce() {
  static std::once_flag f;
  std::call_once(f, removeDeprecatedEventKeysOnceHelper);
}

} // namespace

FLAG(bool,
     events_optimize,
     true,
     "Optimize subscriber select queries (scheduler only)");

// Access this flag through EventSubscriberPlugin::getEventsExpiry to allow for
// overriding in subclasses
FLAG(uint64, events_expiry, 3600, "Timeout to expire event subscriber results");

// Access this flag through EventSubscriberPlugin::getEventBatchesMax to allow
// for overriding in subclasses
FLAG(uint64,
     events_max,
     50000,
     "Maximum number of event batches per type to buffer");

CREATE_REGISTRY(EventSubscriberPlugin, "event_subscriber");

EventSubscriberPlugin::EventSubscriberPlugin(bool enabled)
    : disabled(!enabled) {}

Status EventSubscriberPlugin::init() {
  return Status::success();
}

Status EventSubscriberPlugin::call(const PluginRequest&, PluginResponse&) {
  return Status(0);
}

Status EventSubscriberPlugin::add(const Row& r) {
  std::vector<Row> batch = {r};
  return addBatch(batch, getTime());
}

Status EventSubscriberPlugin::addBatch(std::vector<Row>& row_list) {
  return addBatch(row_list, getUnixTime());
}

Status EventSubscriberPlugin::addBatch(std::vector<Row>& row_list,
                                       EventTime custom_event_time) {
  removeDeprecatedEventKeysOnce();

  DatabaseStringValueList database_data;
  database_data.reserve(row_list.size());

  EventIDList event_id_list;
  event_id_list.reserve(row_list.size());

  auto event_time = custom_event_time != 0 ? custom_event_time : getTime();
  auto string_event_time = std::to_string(event_time);

  for (auto& row : row_list) {
    auto event_identifier = getEventID();
    event_id_list.push_back(event_identifier);

    auto string_event_identifier = toIndex(event_identifier);

    row["time"] = string_event_time;
    row["eid"] = string_event_identifier;

    // Serialize and store the row data, for query-time retrieval.
    std::string serialized_row;
    auto status = serializeRowJSON(row, serialized_row);
    if (!status.ok()) {
      VLOG(1) << status.getMessage();
      continue;
    }

    // Then remove the newline.
    if (serialized_row.size() > 0 && serialized_row.back() == '\n') {
      serialized_row.pop_back();
    }

    // Logger plugins may request events to be forwarded directly.
    // If no active logger is marked 'usesLogEvent' then this is a no-op.
    EventFactory::forwardEvent(serialized_row);

    // Store the event data in the batch
    database_data.push_back(
        std::make_pair("data." + dbNamespace() + "." + string_event_identifier,
                       serialized_row));
  }

  if (database_data.empty()) {
    return Status(1, "Failed to process the rows");
  }

  // Save the batched data inside the database and update the event index
  bool cleanup_events{false};

  {
    WriteLock lock(event_id_lock_);

    auto status = setDatabaseBatch(kEvents, database_data);
    if (!status.ok()) {
      return status;
    }

    auto it = context.event_index.find(event_time);
    if (it == context.event_index.end()) {
      context.event_index.insert({event_time, event_id_list});

    } else {
      auto& index_entry = it->second;
      index_entry.insert(
          index_entry.end(), event_id_list.begin(), event_id_list.end());
    }

    cleanup_events = (((event_count_ % kEventsCheckpoint) + row_list.size()) >=
                      kEventsCheckpoint);
    event_count_ += row_list.size();
  }

  // Use the last EventID and a checkpoint bucket size to periodically apply
  // buffer eviction. Eviction occurs if the total count exceeds events_max.
  if (cleanup_events) {
    removeOverflowingEventBatches(context, getDatabase(), getEventBatchesMax());

    expireEventBatches(context, getDatabase(), getMinExpiry(), getTime());
  }

  return Status::success();
}

Status EventSubscriberPlugin::generateEventDataIndex() {
  return generateEventDataIndex(context, getDatabase());
}

EventID EventSubscriberPlugin::getEventID() {
  return generateEventIdentifier(context);
}

size_t EventSubscriberPlugin::getEventsExpiry() {
  return FLAGS_events_expiry;
}

size_t EventSubscriberPlugin::getEventBatchesMax() {
  return FLAGS_events_max;
}

bool EventSubscriberPlugin::shouldOptimize() const {
  return isDaemon() && FLAGS_events_optimize;
}

void EventSubscriberPlugin::resetQueryCount(size_t count) {
  WriteLock subscriber_lock(event_query_record_);
  queries_.clear();
  query_count_ = count;
}

void EventSubscriberPlugin::setExecutedQuery(const std::string& query_name,
                                             uint64_t query_time) {
  WriteLock lock(event_query_record_);
  queries_[query_name] = query_time;
}

size_t EventSubscriberPlugin::getMinExpiry() {
  auto expiry = getEventsExpiry();
  if (expiry < min_expiration_) {
    return min_expiration_;
  }
  return expiry;
}

void EventSubscriberPlugin::setMinExpiry(size_t expiry) {
  min_expiration_ = expiry;
}

uint64_t EventSubscriberPlugin::getExpireTime() {
  if (query_count_ == 0) {
    return getTime();
  }

  WriteLock subscriber_lock(event_query_record_);
  auto it = std::min_element(
      std::begin(queries_),
      std::end(queries_),
      [](const auto& l, const auto& r) { return l.second < r.second; });
  return it == queries_.end() ? getTime() : it->second;
}

void EventSubscriberPlugin::generateRows(std::function<void(Row)> callback,
                                         bool can_optimize,
                                         EventTime start_time,
                                         EventTime stop_time) {
  EventTime optimize_time{0U};
  EventID optimize_eid{0U};
  if (can_optimize && shouldOptimize()) {
    // If the daemon is querying a subscriber without a 'time' constraint and
    // allows optimization, only emit events since the last query.
    std::string query_name;
    getOptimizeData(getDatabase(), optimize_time, optimize_eid, query_name);
    start_time = optimize_time == 0 ? 0 : optimize_time - 1;

    // Track the queries that have selected data.
    setExecutedQuery(query_name, start_time);
  }

  {
    auto last = generateRows(this->context,
                             getDatabase(),
                             callback,
                             start_time,
                             stop_time,
                             optimize_eid);

    if (can_optimize && shouldOptimize()) {
      if (last != this->context.event_index.end()) {
        auto last_eid = last->second.empty() ? 0 : last->second.back();
        setOptimizeData(getDatabase(), last->first, last_eid);
      }
    }
  }

  if (executedAllQueries()) {
    expireEventBatches(
        this->context, getDatabase(), getMinExpiry(), getExpireTime());
  }
}

void EventSubscriberPlugin::genTable(RowYield& yield, QueryContext& context) {
  // Stop is an unsigned (-1), our end of time equivalent.
  EventTime start = 0, stop = 0;
  bool can_optimize{true};
  if (context.constraints["time"].getAll().size() > 0) {
    can_optimize = false;
    // Use the 'time' constraint to optimize backing-store lookups.
    for (const auto& constraint : context.constraints["time"].getAll()) {
      EventTime expr = timeFromRecord(constraint.expr);
      if (constraint.op == EQUALS) {
        stop = start = expr;
        break;
      } else if (constraint.op == GREATER_THAN) {
        start = std::max(start, expr + 1);
      } else if (constraint.op == GREATER_THAN_OR_EQUALS) {
        start = std::max(start, expr);
      } else if (constraint.op == LESS_THAN) {
        stop = std::min(stop, expr - 1);
      } else if (constraint.op == LESS_THAN_OR_EQUALS) {
        stop = std::min(stop, expr);
      }
    }
  }

  auto generateRowsCallback = [&yield](Row row) {
    yield(TableRowHolder(new DynamicTableRow(std::move(row))));
  };

  generateRows(generateRowsCallback, can_optimize, start, stop);
}

size_t EventSubscriberPlugin::numSubscriptions() const {
  return subscription_count_;
}

EventContextID EventSubscriberPlugin::numEvents() const {
  return event_count_;
}

bool EventSubscriberPlugin::executedAllQueries() const {
  ReadLock lock(event_query_record_);
  return queries_.size() >= query_count_;
}

std::string EventSubscriberPlugin::toIndex(std::uint64_t i) {
  auto str_index = std::to_string(i);
  if (str_index.size() < 10) {
    str_index.insert(str_index.begin(), 10 - str_index.size(), '0');
  }
  return str_index;
}

void EventSubscriberPlugin::setOptimizeData(IDatabaseInterface& db_interface,
                                            EventTime time,
                                            EventID eid) {
  // Store the optimization time and eid.
  std::string query_name;
  db_interface.getDatabaseValue(
      kPersistentSettings, kExecutingQuery, query_name);
  if (query_name.empty()) {
    return;
  }

  db_interface.setDatabaseValue(
      kEvents, "optimize." + query_name, std::to_string(time));

  db_interface.setDatabaseValue(
      kEvents, "optimize_eid." + query_name, toIndex(eid));
}

EventTime EventSubscriberPlugin::timeFromRecord(const std::string& record) {
  // Convert a stored index "as string bytes" to a time value.
  return static_cast<EventTime>(tryTo<long long>(record).takeOr(0ll));
}

void EventSubscriberPlugin::getOptimizeData(IDatabaseInterface& db_interface,
                                            EventTime& o_time,
                                            EventID& o_eid,
                                            std::string& query_name) {
  // Read the optimization time for the current executing query.
  db_interface.getDatabaseValue(
      kPersistentSettings, kExecutingQuery, query_name);

  if (query_name.empty()) {
    o_time = 0;
    o_eid = 0;
    return;
  }

  {
    std::string content;
    db_interface.getDatabaseValue(kEvents, "optimize." + query_name, content);
    o_time = timeFromRecord(content);
  }

  {
    std::string content;
    db_interface.getDatabaseValue(
        kEvents, "optimize_eid." + query_name, content);

    o_eid = tryTo<EventID>(content).takeOr(EventID{0});
  }
}

EventID EventSubscriberPlugin::generateEventIdentifier(Context& context) {
  return ++context.last_event_id;
}

void EventSubscriberPlugin::setDatabaseNamespace(Context& context,
                                                 const std::string& type,
                                                 const std::string& name) {
  context.database_namespace = type + "." + name;
}

Status EventSubscriberPlugin::generateEventDataIndex(
    Context& context, IDatabaseInterface& db_interface) {
  std::vector<std::string> key_list;

  std::string prefix = "data." + context.database_namespace + ".";
  auto status = db_interface.scanDatabaseKeys(kEvents, key_list, prefix, 0);
  if (!status.ok()) {
    return status;
  }

  std::vector<std::string> invalid_data_key_list;
  std::size_t event_count{0U};

  EventID last_event_id{1U};
  EventIndex event_index;

  for (const auto& key : key_list) {
    auto string_event_id = &key[prefix.size()];

    EventID event_identifier = {};

    {
      char* null_terminator = nullptr;
      auto int_value = std::strtoull(string_event_id, &null_terminator, 10);
      if (int_value == 0U || null_terminator == nullptr ||
          *null_terminator != '\0') {
        invalid_data_key_list.push_back(key);
        continue;
      }

      event_identifier = static_cast<EventID>(int_value);
    }

    last_event_id = std::max(last_event_id, event_identifier);

    EventTime event_time = {};

    {
      std::string serialized_row;
      status = db_interface.getDatabaseValue(kEvents, key, serialized_row);
      if (!status.ok()) {
        invalid_data_key_list.push_back(key);
        continue;
      }

      Row row;
      if (!deserializeRowJSON(serialized_row, row)) {
        invalid_data_key_list.push_back(key);
        continue;
      }

      if (row.count("time") == 0) {
        invalid_data_key_list.push_back(key);
        continue;
      }

      event_time = boost::lexical_cast<EventTime>(row.at("time"));
    }

    auto it = event_index.find(event_time);
    if (it == event_index.end()) {
      auto insert_status = event_index.insert({event_time, {}});
      it = insert_status.first;
    }

    auto& event_id_list = it->second;
    event_id_list.push_back(event_identifier);

    ++event_count;
  }

  if (!invalid_data_key_list.empty()) {
    VLOG(1) << "Found " << invalid_data_key_list.size()
            << " invalid events for subscriber " << context.database_namespace;

    for (const auto& invalid_data_key : invalid_data_key_list) {
      status = db_interface.deleteDatabaseValue(kEvents, invalid_data_key);
      if (!status.ok()) {
        VLOG(1) << "Failed to delete the following invalid event: "
                << invalid_data_key;
      }
    }
  }

  if (event_count != 0U) {
    VLOG(1) << "Found " << event_count << " events for subscriber "
            << context.database_namespace;
  }

  context.last_event_id = last_event_id;
  context.event_index = std::move(event_index);

  return Status::success();
}

std::string EventSubscriberPlugin::databaseKeyForEventId(Context& context,
                                                         EventID event_id) {
  auto string_event_id = toIndex(event_id);

  return std::string("data.") + context.database_namespace + "." +
         string_event_id;
}

void EventSubscriberPlugin::removeOverflowingEventBatches(
    Context& context,
    IDatabaseInterface& db_interface,
    std::size_t max_event_batches) {
  if (max_event_batches == 0U) {
    return;
  }

  EventIndex excess_event_batch_list;

  {
    WriteLock lock(context.event_index_mutex);
    if (context.event_index.size() <= max_event_batches) {
      return;
    }

    auto batches_to_remove = context.event_index.size() - max_event_batches;
    auto range_start = context.event_index.begin();
    auto range_end = std::next(range_start, batches_to_remove);

    excess_event_batch_list.insert(std::make_move_iterator(range_start),
                                   std::make_move_iterator(range_end));

    context.event_index.erase(range_start, range_end);
  }

  if (excess_event_batch_list.empty()) {
    return;
  }

  std::string string_last_query_time;
  if (context.last_query_time == 0) {
    string_last_query_time = "never";

  } else {
    auto temp1 = static_cast<std::time_t>(context.last_query_time);

    std::tm temp2{};
    localtime_r(&temp1, &temp2);

    std::array<char, 32U> buffer;
    std::strftime(buffer.data(), buffer.size(), "%F %T", &temp2);

    string_last_query_time = buffer.data();
  }

  std::size_t batches_removed{};
  for (const auto& p : excess_event_batch_list) {
    const auto& event_identifier_list = p.second;

    for (auto event_id : event_identifier_list) {
      auto key = databaseKeyForEventId(context, event_id);
      auto status = db_interface.deleteDatabaseValue(kEvents, key);
      if (status.ok()) {
        ++batches_removed;
      }
    }
  }

  auto failed_delete_count = (excess_event_batch_list.size() - batches_removed);

  std::stringstream message;
  message << "Removed " << batches_removed << " event batches ";

  if (failed_delete_count > 0U) {
    message << "(with " << failed_delete_count << " delete errors)  ";
  }

  message << "for subscriber: " << context.database_namespace
          << " (limit: " << max_event_batches
          << ", last query: " << string_last_query_time << ")";

  LOG(WARNING) << message.str();
}

void EventSubscriberPlugin::expireEventBatches(Context& context,
                                               IDatabaseInterface& db_interface,
                                               std::size_t events_expiry,
                                               std::size_t current_time) {
  if (events_expiry == 0 || current_time == 0) {
    return;
  }

  EventIndex expired_event_batch_list;

  {
    WriteLock lock(context.event_index_mutex);
    if (context.event_index.empty()) {
      return;
    }

    auto oldest_valid_time = current_time - events_expiry;

    auto oldest_event_time = context.event_index.begin()->first;
    if (oldest_event_time >= oldest_valid_time) {
      return;
    }

    auto range_start = context.event_index.begin();
    auto range_end = context.event_index.upper_bound(oldest_valid_time);

    expired_event_batch_list.insert(std::make_move_iterator(range_start),
                                    std::make_move_iterator(range_end));

    context.event_index.erase(range_start, range_end);
  }

  // TODO(alessandro): Implement deleteDatabaseBatch
  std::size_t error_count{};

  for (const auto& p : expired_event_batch_list) {
    const auto& event_identifier_list = p.second;

    for (const auto& event_identifier : event_identifier_list) {
      auto key = databaseKeyForEventId(context, event_identifier);
      auto status = db_interface.deleteDatabaseValue(kEvents, key);
      if (!status.ok()) {
        ++error_count;
      }
    }
  }

  if (error_count > 0U) {
    LOG(ERROR) << "Failed to expire " << error_count
               << " events due to database errors";
  }
}

EventIndex::iterator EventSubscriberPlugin::generateRows(
    Context& context,
    IDatabaseInterface& db_interface,
    std::function<void(Row)> callback,
    EventTime start_time,
    EventTime end_time,
    EventID last_eid) {
  auto last = context.event_index.end();
  if (end_time != 0 && start_time > end_time) {
    return last;
  }

  EventIndex::iterator lower_bound_it;
  if (start_time == 0U) {
    lower_bound_it = context.event_index.begin();

  } else {
    lower_bound_it = context.event_index.lower_bound(start_time);
    if (lower_bound_it == context.event_index.end()) {
      return last;
    }
  }

  auto upper_bound_it = (end_time == 0U)
                            ? context.event_index.end()
                            : context.event_index.upper_bound(end_time);

  std::vector<std::string> invalid_key_list;
  for (auto it = lower_bound_it; it != upper_bound_it; ++it) {
    const auto& event_id_list = it->second;

    for (const auto& event_identifier : event_id_list) {
      if (last_eid >= event_identifier) {
        // A previous optimized query has already visited this event.
        continue;
      }
      auto key = databaseKeyForEventId(context, event_identifier);

      std::string serialized_row;
      auto status = db_interface.getDatabaseValue(kEvents, key, serialized_row);
      if (serialized_row.empty()) {
        invalid_key_list.push_back(key);
        continue;
      }

      Row row = {};
      status = deserializeRowJSON(serialized_row, row);
      if (!status.ok()) {
        invalid_key_list.push_back(key);
        continue;
      }

      callback(std::move(row));
    }
    last = it;
  }

  if (!invalid_key_list.empty()) {
    std::size_t erased_key_count{0U};

    for (const auto& key : invalid_key_list) {
      auto status = db_interface.deleteDatabaseValue(kEvents, key);
      if (status.ok()) {
        ++erased_key_count;
      }
    }

    LOG(ERROR) << "Found " << invalid_key_list.size() << " invalid events ("
               << erased_key_count << " have been successfully erased)";
  }
  return last;
}

const std::string EventSubscriberPlugin::dbNamespace() const {
  return getType() + '.' + getName();
}

uint64_t EventSubscriberPlugin::getTime() const {
  return getUnixTime();
}

IDatabaseInterface& EventSubscriberPlugin::getDatabase() const {
  return getOsqueryDatabase();
}

EventPublisherRef EventSubscriberPlugin::getPublisher() const {
  return EventFactory::getEventPublisher(getType());
}

void EventSubscriberPlugin::removeSubscriptions() {
  subscription_count_ = 0;
  auto publisher = getPublisher();
  if (publisher == nullptr) {
    LOG(WARNING) << "Cannot remove subscriptions from: " << getName();
    return;
  }

  getPublisher()->removeSubscriptions(getName());
}

void EventSubscriberPlugin::setDatabaseNamespace() {
  setDatabaseNamespace(context, getType(), getName());
}

Status EventSubscriberPlugin::setUp() {
  setDatabaseNamespace();
  generateEventDataIndex();

  expireEventBatches(context, getDatabase(), getMinExpiry(), getTime());

  removeOverflowingEventBatches(context, getDatabase(), getEventBatchesMax());

  return Status::success();
}

} // namespace osquery
