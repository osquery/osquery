/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <chrono>
#include <exception>
#include <thread>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/lexical_cast.hpp>

#include <osquery/config.h>
#include <osquery/database.h>
#include <osquery/events.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/system.h>

#include "osquery/core/conversions.h"

namespace osquery {

CREATE_REGISTRY(EventPublisherPlugin, "event_publisher");
CREATE_REGISTRY(EventSubscriberPlugin, "event_subscriber");

/// Checkpoint interval to inspect max event buffering.
#define EVENTS_CHECKPOINT 256

FLAG(bool, disable_events, false, "Disable osquery publish/subscribe system");

FLAG(bool,
     events_optimize,
     true,
     "Optimize subscriber select queries (scheduler only)");

// Access this flag through EventSubscriberPlugin::getEventsExpiry to allow for
// overriding in subclasses
FLAG(uint64, events_expiry, 3600, "Timeout to expire event subscriber results");

// Access this flag through EventSubscriberPlugin::getEventsMax to allow for
// overriding in subclasses
FLAG(uint64, events_max, 50000, "Maximum number of events per type to buffer");

static inline EventTime timeFromRecord(const std::string& record) {
  // Convert a stored index "as string bytes" to a time value.
  long long afinite;
  if (!safeStrtoll(record, 10, afinite)) {
    return 0;
  }
  return afinite;
}

static inline std::string toIndex(size_t i) {
  auto j = std::to_string(i);
  size_t n = 1;
  while (i /= 10) {
    n++;
  }
  return (n >= 10) ? j : std::string(10 - n, '0').append(std::move(j));
}

static inline void getOptimizeData(EventTime& o_time,
                                   size_t& o_eid,
                                   std::string& query_name,
                                   const std::string& publisher) {
  // Read the optimization time for the current executing query.
  getDatabaseValue(kPersistentSettings, kExecutingQuery, query_name);
  if (query_name.empty()) {
    o_time = 0;
    o_eid = 0;
    return;
  }

  {
    std::string content;
    getDatabaseValue(kEvents, "optimize." + query_name, content);
    long long optimize_time = 0;
    safeStrtoll(content, 10, optimize_time);
    o_time = static_cast<EventTime>(optimize_time);
  }

  {
    std::string content;
    getDatabaseValue(kEvents, "optimize_eid." + query_name, content);
    long long optimize_eid = 0;
    safeStrtoll(content, 10, optimize_eid);
    o_eid = static_cast<size_t>(optimize_eid);
  }
}

static inline void setOptimizeData(EventTime time,
                                   size_t eid,
                                   const std::string& publisher) {
  // Store the optimization time and eid.
  std::string query_name;
  getDatabaseValue(kPersistentSettings, kExecutingQuery, query_name);
  if (query_name.empty()) {
    return;
  }

  setDatabaseValue(kEvents, "optimize." + query_name, std::to_string(time));
  setDatabaseValue(kEvents, "optimize_eid." + query_name, toIndex(eid));
}

void EventSubscriberPlugin::genTable(RowYield& yield, QueryContext& context) {
  // Stop is an unsigned (-1), our end of time equivalent.
  EventTime start = 0, stop = 0;
  if (context.constraints["time"].getAll().size() > 0) {
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
  } else if (Initializer::isDaemon() && FLAGS_events_optimize) {
    // If the daemon is querying a subscriber without a 'time' constraint and
    // allows optimization, only emit events since the last query.
    std::string query_name;
    getOptimizeData(optimize_time_, optimize_eid_, query_name, dbNamespace());
    start = optimize_time_;
    optimize_time_ = getUnixTime() - 1;

    // Track the queries that have selected data.
    WriteLock lock(event_query_record_);
    if (!query_name.empty() && queries_.count(query_name) == 0) {
      queries_.insert(query_name);
    }
  }
  get(yield, start, stop);
}

void EventPublisherPlugin::fire(const EventContextRef& ec, EventTime time) {
  if (isEnding()) {
    // Cannot emit/fire while ending
    return;
  }

  EventContextID ec_id = 0;
  {
    WriteLock lock(ec_id_lock_);
    ec_id = next_ec_id_++;
  }

  // Fill in EventContext ID and time if needed.
  if (ec != nullptr) {
    ec->id = ec_id;
    if (ec->time == 0) {
      if (time == 0) {
        time = getUnixTime();
      }
      ec->time = time;
    }
  }

  WriteLock lock(subscription_lock_);
  for (const auto& subscription : subscriptions_) {
    auto es = EventFactory::getEventSubscriber(subscription->subscriber_name);
    if (es != nullptr && es->state() == EventState::EVENT_RUNNING) {
      fireCallback(subscription, ec);
    }
  }
}

std::vector<std::string> EventSubscriberPlugin::getIndexes(EventTime start,
                                                           EventTime stop,
                                                           bool sort) {
  auto index_key = "indexes." + dbNamespace();
  std::vector<std::string> indexes;

  EventTime l_start = (start > 0) ? start / 60 : 0;
  EventTime r_stop = (stop > 0) ? stop / 60 + 1 : 0;

  std::string content;
  getDatabaseValue(kEvents, index_key + ".60", content);
  if (content.empty()) {
    return indexes;
  }

  std::vector<std::string> bins, expirations;
  boost::split(bins, content, boost::is_any_of(","));
  for (const auto& bin : bins) {
    auto step = timeFromRecord(bin);
    auto step_start = step * 60;
    auto step_stop = (step + 1) * 60;
    if (step_stop <= expire_time_) {
      expirations.push_back(bin);
    } else if (step_start < expire_time_ && sort) {
      expireRecords("60", bin, false);
    }

    if (step >= l_start && (r_stop == 0 || step < r_stop) && sort) {
      indexes.push_back("60." + bin);
    }
  }

  // Rewrite the index lists and delete each expired item.
  if (!expirations.empty()) {
    expireIndexes("60", bins, expirations);
  }

  // Return indexes in binning order.
  if (sort) {
    std::sort(indexes.begin(),
              indexes.end(),
              [](const std::string& left, const std::string& right) {
                auto n1 = timeFromRecord(left.substr(left.find('.') + 1));
                auto n2 = timeFromRecord(right.substr(right.find('.') + 1));
                return n1 < n2;
              });
  }

  // Update the new time that events expire to now - expiry.
  return indexes;
}

void EventSubscriberPlugin::expireRecords(const std::string& list_type,
                                          const std::string& index,
                                          bool all) {
  if (!executedAllQueries()) {
    return;
  }

  auto record_key = "records." + dbNamespace();
  auto data_key = "data." + dbNamespace();

  // If the expirations is not removing all records, rewrite the persisting.
  std::vector<std::string> persisting_records;
  // Request all records within this list-size + bin offset.
  auto expired_records = getRecords({list_type + '.' + index}, false);
  if (all && expired_records.size() > 1) {
    deleteDatabaseRange(kEvents,
                        data_key + '.' + expired_records.begin()->first,
                        data_key + '.' + expired_records.rbegin()->first);
  } else {
    for (const auto& record : expired_records) {
      if (record.second <= expire_time_) {
        deleteDatabaseValue(kEvents, data_key + '.' + record.first);
      } else {
        persisting_records.push_back(record.first + ':' +
                                     std::to_string(record.second));
      }
    }
  }

  // Either drop or overwrite the record list.
  if (all) {
    deleteDatabaseValue(kEvents, record_key + "." + list_type + "." + index);
  } else if (persisting_records.size() < expired_records.size()) {
    auto new_records = boost::algorithm::join(persisting_records, ",");
    setDatabaseValue(
        kEvents, record_key + "." + list_type + "." + index, new_records);
  }
}

void EventSubscriberPlugin::expireIndexes(
    const std::string& list_type,
    const std::vector<std::string>& indexes,
    const std::vector<std::string>& expirations) {
  if (!executedAllQueries()) {
    return;
  }

  auto index_key = "indexes." + dbNamespace();

  // Construct a mutable list of persisting indexes to rewrite as records.
  std::vector<std::string> persisting_indexes = indexes;
  // Remove the records using the list of expired indexes.
  for (const auto& bin : expirations) {
    expireRecords(list_type, bin, true);
    persisting_indexes.erase(
        std::remove(persisting_indexes.begin(), persisting_indexes.end(), bin),
        persisting_indexes.end());
  }

  // Update the list of indexes with the non-expired indexes.
  auto new_indexes = boost::algorithm::join(persisting_indexes, ",");
  setDatabaseValue(kEvents, index_key + "." + list_type, new_indexes);
}

void EventSubscriberPlugin::expireCheck() {
  auto data_key = "data." + dbNamespace();
  auto eid_key = "eid." + dbNamespace();
  // Min key will be the last surviving key.
  size_t threshold_key = 0;

  {
    auto limit = getEventsMax();
    std::vector<std::string> keys;
    scanDatabaseKeys(kEvents, keys, data_key);
    if (keys.size() <= limit) {
      return;
    }

    // There is an overflow of events buffered for this subscriber.
    LOG(WARNING) << "Expiring events for subscriber: " << getName()
                 << " (overflowed limit " << limit << ")";
    VLOG(1) << "Subscriber events " << getName() << " exceeded limit " << limit
            << " by: " << keys.size() - limit;
    // Inspect the N-FLAGS_events_max -th event's value and expire before the
    // time within the content.
    std::string last_key;
    getDatabaseValue(kEvents, eid_key, last_key);
    // The EID is the next-index.
    // EID - events_max is the most last-recent event to keep.
    threshold_key = boost::lexical_cast<size_t>(last_key) - getEventsMax();

    // Scan each of the keys in keys, if their ID portion is < threshold.
    // Nix them, this requires lots of conversions, use with care.
    std::string max_key;
    std::string min_key;
    unsigned long min_key_value = 0;
    unsigned long max_key_value = 0;
    for (const auto& key : keys) {
      unsigned long key_value = 0;
      safeStrtoul(key.substr(key.rfind('.') + 1), 10, key_value);

      if (key_value < static_cast<unsigned long>(threshold_key)) {
        min_key_value = (min_key_value == 0 || key_value < min_key_value)
                            ? key_value
                            : min_key_value;
        if (min_key_value == key_value) {
          min_key = key;
        }

        max_key_value = (key_value > max_key_value) ? key_value : max_key_value;
        if (max_key_value == key_value) {
          max_key = key;
        }
      }
    }

    if (!min_key.empty()) {
      if (max_key_value == min_key_value) {
        deleteDatabaseValue(kEvents, min_key);
      } else {
        deleteDatabaseRange(kEvents, min_key, max_key);
      }
    }
  }

  // Convert the key index into a time using the content.
  // The last-recent event is fetched and the corresponding time is used as
  // the expiration time for the subscriber.
  std::string content;
  getDatabaseValue(kEvents, data_key + "." + toIndex(threshold_key), content);

  // Decode the value into a row structure to extract the time.
  Row r;
  if (!deserializeRowJSON(content, r) || r.count("time") == 0) {
    return;
  }

  // The last time will become the implicit expiration time.
  size_t last_time = boost::lexical_cast<size_t>(r.at("time"));
  if (last_time > 0) {
    expire_time_ = last_time - (last_time % 60);
  }

  // Finally, attempt an index query to trigger expirations.
  // In this case the result set is not used.
  getIndexes(expire_time_, 0, false);
}

bool EventSubscriberPlugin::executedAllQueries() const {
  ReadLock lock(event_query_record_);
  return queries_.size() >= query_count_;
}

std::vector<EventRecord> EventSubscriberPlugin::getRecords(
    const std::vector<std::string>& indexes, bool optimize) {
  auto record_key = "records." + dbNamespace();

  std::vector<EventRecord> records;
  for (const auto& index : indexes) {
    std::vector<std::string> bin_records;
    {
      std::string record_value;
      getDatabaseValue(kEvents, record_key + "." + index, record_value);
      if (record_value.empty()) {
        // There are actually no events in this bin, interesting error case.
        continue;
      }

      // Each list is tokenized into a record=event_id:time.
      boost::split(bin_records, record_value, boost::is_any_of(",:"));
    }

    auto bin_it = bin_records.begin();
    // Iterate over every 2 items: EID:TIME.
    for (; bin_it != bin_records.end(); bin_it++) {
      const auto& eid = *bin_it;
      EventTime et = timeFromRecord(*(++bin_it));
      if (FLAGS_events_optimize && optimize && et <= optimize_time_ + 1) {
        // There is an optimization collision, check for colliding IDs.
        auto eidr = timeFromRecord(eid);
        if (eidr <= optimize_eid_) {
          continue;
        }
      }
      records.push_back(std::make_pair(eid, et));
    }
  }

  return records;
}

Status EventSubscriberPlugin::recordEvent(EventID& eid, EventTime et) {
  std::string time_value = boost::lexical_cast<std::string>(et);

  // The record is identified by the event type then module name.
  std::string index_key = "indexes." + dbNamespace();
  std::string record_key = "records." + dbNamespace();
  // The list key includes the list type (bin size) and the list ID (bin).
  std::string list_id;

  // The list_id is the MOST-Specific key ID, the bin for this list.
  // If the event time was 13 and the time_list is 5 seconds, lid = 2.
  list_id = boost::lexical_cast<std::string>(et / 60);

  WriteLock lock(event_record_lock_);
  // Append the record (eid, unix_time) to the list bin.
  std::string record_value;
  getDatabaseValue(kEvents, record_key + ".60." + list_id, record_value);

  if (record_value.length() == 0) {
    // This is a new list_id for list_key, append the ID to the indirect
    // lookup for this list_key.
    std::string index_value;
    getDatabaseValue(kEvents, index_key + ".60", index_value);
    if (index_value.length() == 0) {
      // A new index.
      index_value = list_id;
    } else {
      index_value += "," + list_id;
    }
    setDatabaseValue(kEvents, index_key + ".60", index_value);
    record_value = eid + ":" + time_value;
  } else {
    // Tokenize a record using ',' and the EID/time using ':'.
    record_value += "," + eid + ":" + time_value;
  }
  auto status =
      setDatabaseValue(kEvents, record_key + ".60." + list_id, record_value);
  if (!status.ok()) {
    LOG(ERROR) << "Could not put Event Record key: " << record_key;
  }
  return Status(0, "OK");
}

size_t EventSubscriberPlugin::getEventsExpiry() {
  return FLAGS_events_expiry;
}

size_t EventSubscriberPlugin::getEventsMax() {
  return FLAGS_events_max;
}

EventID EventSubscriberPlugin::getEventID() {
  Status status;
  // First get an event ID from the meta key.
  std::string eid_key = "eid." + dbNamespace();

  {
    WriteLock lock(event_id_lock_);
    if (last_eid_ == 0) {
      std::string last_eid_value;
      status = getDatabaseValue(kEvents, eid_key, last_eid_value);
      if (!status.ok() || last_eid_value.empty()) {
        last_eid_value = "0";
      }
      last_eid_ = boost::lexical_cast<size_t>(last_eid_value);
    }

    if (last_eid_ % 10 == 0) {
      status = setDatabaseValue(kEvents, eid_key, toIndex(last_eid_ + 10));
    }
    last_eid_++;
  }

  return toIndex(last_eid_);
}

void EventSubscriberPlugin::get(RowYield& yield,
                                EventTime start,
                                EventTime stop) {
  // Get the records for this time range.
  auto indexes = getIndexes(start, stop);
  auto records = getRecords(indexes);

  std::string events_key = "data." + dbNamespace();
  std::vector<std::string> mapped_records;
  for (const auto& record : records) {
    if (record.second >= start && (record.second <= stop || stop == 0)) {
      mapped_records.push_back(events_key + "." + record.first);
    }
  }

  if (FLAGS_events_optimize && !records.empty()) {
    // If records were returned save the ordered-last as the optimization EID.
    unsigned long int eidr = 0;
    if (safeStrtoul(records.back().first, 10, eidr)) {
      optimize_eid_ = static_cast<size_t>(eidr);
    }
  }

  // Select mapped_records using event_ids as keys.
  std::string data_value;
  for (const auto& record : mapped_records) {
    Row r;
    auto status = getDatabaseValue(kEvents, record, data_value);
    if (data_value.length() == 0) {
      // There is no record here, interesting error case.
      continue;
    }
    status = deserializeRowJSON(data_value, r);
    data_value.clear();
    if (status.ok()) {
      yield(r);
    }
  }

  auto expiry = getEventsExpiry();
  if (expiry > 0) {
    // Make sure the configured expiration is at least the minimum needed to
    // execute all related queries in the schedule.
    if (expiry < min_expiration_) {
      expiry = min_expiration_;
    }

    // Set the expire time to NOW - "configured lifetime".
    // Index retrieval will apply the constraints checking and auto-expire.
    expire_time_ = getUnixTime() - expiry;
    expire_time_ = expire_time_ - (expire_time_ % 60);
  }

  if (FLAGS_events_optimize) {
    setOptimizeData(optimize_time_, optimize_eid_, dbNamespace());
  }
}

Status EventSubscriberPlugin::add(Row& r, EventTime event_time) {
  // Get and increment the EID for this module.
  EventID eid = getEventID();
  // Without encouraging a missing event time, do not support a 0-time.
  if (event_time == 0) {
    event_time = getUnixTime();
  }

  r["time"] = std::to_string(event_time);
  r["eid"] = eid;
  // Serialize and store the row data, for query-time retrieval.
  std::string data;
  auto status = serializeRowJSON(r, data);
  if (!status.ok()) {
    return status;
  }
  // Then remove the newline.
  if (data.size() > 0 && data.back() == '\n') {
    data.pop_back();
  }

  // Use the last EventID and a checkpoint bucket size to periodically apply
  // buffer eviction. Eviction occurs if the total count exceeds events_max.
  if (last_eid_ % EVENTS_CHECKPOINT == 0) {
    expireCheck();
  }

  // Logger plugins may request events to be forwarded directly.
  // If no active logger is marked 'usesLogEvent' then this is a no-op.
  EventFactory::forwardEvent(data);

  // Store the event data.
  std::string event_key = "data." + dbNamespace() + "." + eid;
  status = setDatabaseValue(kEvents, event_key, data);
  // Record the event in the indexing bins, using the index time.
  recordEvent(eid, event_time);
  event_count_++;
  return status;
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

void EventFactory::delay() {
  // Caller may disable event publisher threads.
  if (FLAGS_disable_events) {
    return;
  }

  // Create a thread for each event publisher.
  auto& ef = EventFactory::getInstance();
  for (const auto& publisher : EventFactory::getInstance().event_pubs_) {
    // Publishers that did not set up correctly are put into an ending state.
    if (!publisher.second->isEnding()) {
      auto thread_ = std::make_shared<std::thread>(
          boost::bind(&EventFactory::run, publisher.first));
      ef.threads_.push_back(thread_);
    }
  }
}

Status EventPublisherPlugin::addSubscription(
    const SubscriptionRef& subscription) {
  // The publisher threads may be running and if they fire events the list of
  // subscriptions will be walked.
  WriteLock lock(subscription_lock_);
  subscriptions_.push_back(subscription);
  return Status(0);
}

void EventPublisherPlugin::removeSubscriptions(const std::string& subscriber) {
  // See addSubscription for details on the critical section.
  WriteLock lock(subscription_lock_);
  auto end =
      std::remove_if(subscriptions_.begin(),
                     subscriptions_.end(),
                     [&subscriber](const SubscriptionRef& subscription) {
                       return (subscription->subscriber_name == subscriber);
                     });
  subscriptions_.erase(end, subscriptions_.end());
}

void EventFactory::addForwarder(const std::string& logger) {
  getInstance().loggers_.push_back(logger);
}

void EventFactory::forwardEvent(const std::string& event) {
  for (const auto& logger : getInstance().loggers_) {
    Registry::call("logger", logger, {{"event", event}});
  }
}

void EventFactory::configUpdate() {
  // Scan the schedule for queries that touch "_events" tables.
  // We will count the queries
  std::map<std::string, SubscriberExpirationDetails> subscriber_details;
  Config::get().scheduledQueries([&subscriber_details](
      const std::string& name, const ScheduledQuery& query) {
    std::vector<std::string> tables;
    // Convert query string into a list of virtual tables effected.
    if (!getQueryTables(query.query, tables)) {
      VLOG(1) << "Cannot get tables from query: " << name;
      return;
    }

    // Remove duplicates and select only the subscriber tables.
    std::set<std::string> subscribers;
    for (const auto& table : tables) {
      if (Registry::get().exists("event_subscriber", table)) {
        subscribers.insert(table);
      }
    }

    for (const auto& subscriber : subscribers) {
      auto& details = subscriber_details[subscriber];
      details.max_interval = (query.interval > details.max_interval)
                                 ? query.interval
                                 : details.max_interval;
      details.query_count++;
    }
  });

  auto& ef = EventFactory::getInstance();
  for (const auto& details : subscriber_details) {
    if (!ef.exists(details.first)) {
      continue;
    }

    WriteLock lock(ef.factory_lock_);
    auto subscriber = ef.getEventSubscriber(details.first);
    subscriber->min_expiration_ = details.second.max_interval * 3;
    subscriber->min_expiration_ += (60 - (subscriber->min_expiration_ % 60));

    // Emit a warning for each subscriber affected by the small expiration.
    auto expiry = subscriber->getEventsExpiry();
    if (expiry > 0 && subscriber->min_expiration_ > expiry) {
      LOG(INFO) << "Subscriber expiration is too low: "
                << subscriber->getName();
    }
    subscriber->query_count_ = details.second.query_count;

    WriteLock subscriber_lock(subscriber->event_query_record_);
    subscriber->queries_.clear();
  }

  // If events are enabled configure the subscribers before publishers.
  if (!FLAGS_disable_events) {
    RegistryFactory::get().registry("event_subscriber")->configure();
    RegistryFactory::get().registry("event_publisher")->configure();
  }
}

Status EventFactory::run(EventPublisherID& type_id) {
  if (FLAGS_disable_events) {
    return Status(0, "Events disabled");
  }

  // An interesting take on an event dispatched entrypoint.
  // There is little introspection into the event type.
  // Assume it can either make use of an entrypoint poller/selector or
  // take care of async callback registrations in setUp/configure/run
  // only once and handle event queuing/firing in callbacks.
  EventPublisherRef publisher = nullptr;
  {
    auto& ef = EventFactory::getInstance();
    WriteLock lock(ef.factory_lock_);
    publisher = ef.getEventPublisher(type_id);
  }

  if (publisher == nullptr) {
    return Status(1, "Event publisher is missing");
  } else if (publisher->hasStarted()) {
    return Status(1, "Cannot restart an event publisher");
  }
  VLOG(1) << "Starting event publisher run loop: " + type_id;
  publisher->hasStarted(true);

  auto status = Status(0, "OK");
  while (!publisher->isEnding()) {
    // Can optionally implement a global cooloff latency here.
    status = publisher->run();
    if (!status.ok()) {
      break;
    }
    publisher->restart_count_++;
    // This is a 'default' cool-off implemented in InterruptableRunnable.
    // If a publisher fails to perform some sort of interruption point, this
    // prevents the thread from thrashing through exiting checks.
    publisher->pauseMilli(200);
  }
  if (!status.ok()) {
    // The runloop status is not reflective of the event type's.
    VLOG(1) << "Event publisher " << publisher->type()
            << " run loop terminated for reason: " << status.getMessage();
    // Publishers auto tear down when their run loop stops.
  }
  publisher->tearDown();
  publisher->state(EventState::EVENT_NONE);

  // Do not remove the publisher from the event factory.
  // If the event factory's `end` method was called these publishers will be
  // cleaned up after their thread context is removed; otherwise, a removed
  // thread context and failed publisher will remain available for stats.
  return Status(0, "OK");
}

// There's no reason for the event factory to keep multiple instances.
EventFactory& EventFactory::getInstance() {
  static EventFactory ef;
  return ef;
}

Status EventFactory::registerEventPublisher(const PluginRef& pub) {
  // Try to downcast the plugin to an event publisher.
  EventPublisherRef specialized_pub;
  try {
    auto base_pub = std::dynamic_pointer_cast<EventPublisherPlugin>(pub);
    specialized_pub = std::static_pointer_cast<BaseEventPublisher>(base_pub);
  } catch (const std::bad_cast& /* e */) {
    return Status(1, "Incorrect plugin");
  }

  if (specialized_pub == nullptr || specialized_pub.get() == nullptr) {
    return Status(0, "Invalid publisher");
  }

  auto type_id = specialized_pub->type();
  if (type_id.empty()) {
    // This subscriber did not override its name.
    return Status(1, "Publishers must have a type");
  }

  auto& ef = EventFactory::getInstance();
  {
    WriteLock lock(getInstance().factory_lock_);
    if (ef.event_pubs_.count(type_id) != 0) {
      // This is a duplicate event publisher.
      return Status(1, "Duplicate publisher type");
    }

    // Do not set up event publisher if events are disabled.
    ef.event_pubs_[type_id] = specialized_pub;
  }

  if (!FLAGS_disable_events) {
    if (specialized_pub->state() != EventState::EVENT_NONE) {
      specialized_pub->tearDown();
    }

    auto status = specialized_pub->setUp();
    specialized_pub->state(EventState::EVENT_SETUP);
    if (!status.ok()) {
      // Only start event loop if setUp succeeds.
      LOG(INFO) << "Event publisher failed setup: " << type_id << ": "
                << status.what();
      specialized_pub->isEnding(true);
      return status;
    }
  }

  return Status(0, "OK");
}

Status EventFactory::registerEventSubscriber(const PluginRef& sub) {
  // Try to downcast the plugin to an event subscriber.
  EventSubscriberRef specialized_sub;
  try {
    auto base_sub = std::dynamic_pointer_cast<EventSubscriberPlugin>(sub);
    specialized_sub = std::static_pointer_cast<BaseEventSubscriber>(base_sub);
  } catch (const std::bad_cast& /* e */) {
    return Status(1, "Incorrect plugin");
  }

  if (specialized_sub == nullptr || specialized_sub.get() == nullptr) {
    return Status(1, "Invalid subscriber");
  }

  // The config may use an "events" key to explicitly enabled or disable
  // event subscribers. See EventSubscriber::disable.
  auto name = specialized_sub->getName();
  if (name.empty()) {
    // This subscriber did not override its name.
    return Status(1, "Subscribers must have set a name");
  }

  auto plugin = Config::get().getParser("events");
  if (plugin != nullptr && plugin.get() != nullptr) {
    const auto& data = plugin->getData();
    // First perform explicit enabling.
    if (data.get_child("events").count("enable_subscribers") > 0) {
      for (const auto& item : data.get_child("events.enable_subscribers")) {
        if (item.second.data() == name) {
          VLOG(1) << "Enabling event subscriber: " << name;
          specialized_sub->disabled = false;
        }
      }
    }
    // Then use explicit disabling as an ultimate override.
    if (data.get_child("events").count("disable_subscribers") > 0) {
      for (const auto& item : data.get_child("events.disable_subscribers")) {
        if (item.second.data() == name) {
          VLOG(1) << "Disabling event subscriber: " << name;
          specialized_sub->disabled = true;
        }
      }
    }
  }

  if (specialized_sub->state() != EventState::EVENT_NONE) {
    specialized_sub->tearDown();
  }

  // Allow subscribers a configure-time setup to determine if they should run.
  auto status = specialized_sub->setUp();
  if (!status) {
    specialized_sub->disabled = true;
  }
  specialized_sub->state(EventState::EVENT_SETUP);

  // Let the subscriber initialize any Subscriptions.
  if (!FLAGS_disable_events && !specialized_sub->disabled) {
    specialized_sub->expireCheck();
    status = specialized_sub->init();
    specialized_sub->state(EventState::EVENT_RUNNING);
  } else {
    specialized_sub->state(EventState::EVENT_PAUSED);
  }

  auto& ef = EventFactory::getInstance();
  {
    WriteLock lock(getInstance().factory_lock_);
    ef.event_subs_[name] = specialized_sub;
  }

  // Set state of subscriber.
  if (!status.ok()) {
    specialized_sub->state(EventState::EVENT_FAILED);
    return Status(1, status.getMessage());
  } else {
    return Status(0, "OK");
  }
}

Status EventFactory::addSubscription(EventPublisherID& type_id,
                                     EventSubscriberID& name_id,
                                     const SubscriptionContextRef& mc,
                                     EventCallback cb) {
  auto subscription = Subscription::create(name_id, mc, cb);
  return EventFactory::addSubscription(type_id, subscription);
}

Status EventFactory::addSubscription(EventPublisherID& type_id,
                                     const SubscriptionRef& subscription) {
  EventPublisherRef publisher = getInstance().getEventPublisher(type_id);
  if (publisher == nullptr) {
    return Status(1, "Unknown event publisher");
  }

  // The event factory is responsible for configuring the event types.
  return publisher->addSubscription(subscription);
}

size_t EventFactory::numSubscriptions(EventPublisherID& type_id) {
  EventPublisherRef publisher;
  try {
    publisher = EventFactory::getInstance().getEventPublisher(type_id);
  } catch (std::out_of_range& /* e */) {
    return 0;
  }
  if (publisher == nullptr) {
    return 0;
  }
  return publisher->numSubscriptions();
}

EventPublisherRef EventFactory::getEventPublisher(EventPublisherID& type_id) {
  if (getInstance().event_pubs_.count(type_id) == 0) {
    LOG(ERROR) << "Requested unknown/failed event publisher: " + type_id;
    return nullptr;
  }
  return getInstance().event_pubs_.at(type_id);
}

EventSubscriberRef EventFactory::getEventSubscriber(
    EventSubscriberID& name_id) {
  if (!exists(name_id)) {
    LOG(ERROR) << "Requested unknown event subscriber: " + name_id;
    return nullptr;
  }
  return getInstance().event_subs_.at(name_id);
}

bool EventFactory::exists(EventSubscriberID& name_id) {
  return (getInstance().event_subs_.count(name_id) > 0);
}

Status EventFactory::deregisterEventPublisher(const EventPublisherRef& pub) {
  return EventFactory::deregisterEventPublisher(pub->type());
}

Status EventFactory::deregisterEventPublisher(EventPublisherID& type_id) {
  auto& ef = EventFactory::getInstance();

  WriteLock lock(ef.factory_lock_);
  EventPublisherRef publisher = ef.getEventPublisher(type_id);
  if (publisher == nullptr) {
    return Status(1, "No event publisher to deregister");
  }

  if (!FLAGS_disable_events) {
    publisher->isEnding(true);
    if (!publisher->hasStarted()) {
      // If a publisher's run loop was not started, call tearDown since
      // the setUp happened at publisher registration time.
      publisher->tearDown();
      publisher->state(EventState::EVENT_NONE);
      // If the run loop did run the tear down and erase will happen in the
      // event thread wrapper when isEnding is next checked.
      ef.event_pubs_.erase(type_id);
    } else {
      publisher->stop();
    }
  }
  return Status(0, "OK");
}

Status EventFactory::deregisterEventSubscriber(EventSubscriberID& sub) {
  auto& ef = EventFactory::getInstance();

  WriteLock lock(ef.factory_lock_);
  if (ef.event_subs_.count(sub) == 0) {
    return Status(1, "Event subscriber is missing");
  }

  auto& subscriber = ef.event_subs_.at(sub);
  subscriber->state(EventState::EVENT_NONE);
  subscriber->tearDown();
  ef.event_subs_.erase(sub);
  return Status(0);
}

std::vector<std::string> EventFactory::publisherTypes() {
  WriteLock lock(getInstance().factory_lock_);
  std::vector<std::string> types;
  for (const auto& publisher : getInstance().event_pubs_) {
    types.push_back(publisher.first);
  }
  return types;
}

std::vector<std::string> EventFactory::subscriberNames() {
  WriteLock lock(getInstance().factory_lock_);
  std::vector<std::string> names;
  for (const auto& subscriber : getInstance().event_subs_) {
    names.push_back(subscriber.first);
  }
  return names;
}

void EventFactory::end(bool join) {
  auto& ef = EventFactory::getInstance();

  // Call deregister on each publisher.
  for (const auto& publisher : ef.publisherTypes()) {
    deregisterEventPublisher(publisher);
  }

  // Stop handling exceptions for the publisher threads.
  for (const auto& thread : ef.threads_) {
    if (join) {
      thread->join();
    } else {
      thread->detach();
    }
  }

  {
    WriteLock lock(getInstance().factory_lock_);
    // A small cool off helps OS API event publisher flushing.
    if (!FLAGS_disable_events) {
      ef.threads_.clear();
    }

    // Threads may still be executing, when they finish, release publishers.
    ef.event_pubs_.clear();
    ef.event_subs_.clear();
  }
}

void attachEvents() {
  const auto& publishers = RegistryFactory::get().plugins("event_publisher");
  for (const auto& publisher : publishers) {
    EventFactory::registerEventPublisher(publisher.second);
  }

  const auto& subscribers = RegistryFactory::get().plugins("event_subscriber");
  for (const auto& subscriber : subscribers) {
    if (subscriber.first.find("_events") == std::string::npos ||
        subscriber.first.find("_events") + 7 != subscriber.first.size()) {
      LOG(ERROR) << "Error registering subscriber: " << subscriber.first
                 << ": Must use a '_events' suffix";
      continue;
    }

    auto status = EventFactory::registerEventSubscriber(subscriber.second);
    if (!status.ok()) {
      VLOG(1) << "Error registering subscriber: " << subscriber.first << ": "
              << status.getMessage();
    }
  }

  // Configure the event publishers and subscribers.
  EventFactory::configUpdate();
}
}
