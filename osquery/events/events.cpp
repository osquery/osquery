/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <exception>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/lexical_cast.hpp>

#include <osquery/core.h>
#include <osquery/events.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"
#include "osquery/database/db_handle.h"

namespace osquery {

/// Helper cooloff (ms) macro to prevent thread failure thrashing.
#define EVENTS_COOLOFF 20

FLAG(bool, disable_events, false, "Disable osquery publish/subscribe system");

FLAG(bool,
     events_optimize,
     true,
     "Optimize subscriber select queries (scheduler only)");

FLAG(int32, events_expiry, 86000, "Timeout to expire event subscriber results");

const std::vector<size_t> kEventTimeLists = {
    1 * 60 * 60, // 1 hour
    1 * 60, // 1 minute
    10, // 10 seconds
};

void publisherSleep(size_t milli) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(milli));
}

static inline EventTime timeFromRecord(const std::string& record) {
  // Convert a stored index "as string bytes" to a time value.
  char* end = nullptr;
  long long int afinite = strtoll(record.c_str(), &end, 10);
  if (end == nullptr || end == record.c_str() || *end != '\0' ||
      ((afinite == LLONG_MIN || afinite == LLONG_MAX) && errno == ERANGE)) {
    return 0;
  }
  return afinite;
}

QueryData EventSubscriberPlugin::genTable(QueryContext& context) {
  EventTime start = 0, stop = -1;
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
  } else if (kToolType == OSQUERY_TOOL_DAEMON && FLAGS_events_optimize) {
    // If the daemon is querying a subscriber without a 'time' constraint and
    // allows optimization, only emit events since the last query.
    start = optimize_time_;
    optimize_time_ = getUnixTime() - 1;
  }

  return get(start, stop);
}

void EventPublisherPlugin::fire(const EventContextRef& ec, EventTime time) {
  EventContextID ec_id;

  if (isEnding()) {
    // Cannot emit/fire while ending
    return;
  }

  {
    boost::lock_guard<boost::mutex> lock(ec_id_lock_);
    ec_id = next_ec_id_++;
  }

  // Fill in EventContext ID and time if needed.
  if (ec != nullptr) {
    ec->id = ec_id;
    if (ec->time == 0) {
      if (time == 0) {
        time = getUnixTime();
      }
      // Todo: add a check to assure normalized (seconds) time.
      ec->time = time;
    }
  }

  for (const auto& subscription : subscriptions_) {
    auto es = EventFactory::getEventSubscriber(subscription->subscriber_name);
    if (es != nullptr && es->state() == SUBSCRIBER_RUNNING) {
      es->event_count_++;
      fireCallback(subscription, ec);
    }
  }
}

std::set<std::string> EventSubscriberPlugin::getIndexes(EventTime start,
                                                        EventTime stop,
                                                        int list_key) {
  auto db = DBHandle::getInstance();
  auto index_key = "indexes." + dbNamespace();
  std::set<std::string> indexes;

  // Keep track of the tail/head of account time while bin searching.
  EventTime start_max = stop, stop_min = stop, local_start, local_stop;
  auto types = kEventTimeLists.size();
  // List types are sized bins of time containing records for this namespace.
  for (size_t i = 0; i < types; ++i) {
    auto size = kEventTimeLists[i];
    if (list_key > 0 && i != list_key) {
      // A specific list_type was requested, only return bins of this key.
      continue;
    }

    std::string time_list;
    auto list_type = boost::lexical_cast<std::string>(size);
    auto status = db->Get(kEvents, index_key + "." + list_type, time_list);
    if (time_list.length() == 0) {
      // No events in this binning size.
      return indexes;
    }

    if (list_key == 0 && i == (types - 1) && types > 1) {
      // Relax the requested start/stop bounds.
      if (start != start_max) {
        start = (start / size) * size;
        start_max = ((start / size) + 1) * size;
        if (start_max < stop) {
          start_max = start + kEventTimeLists[types - 2];
        }
      }

      if (stop != stop_min) {
        stop = ((stop / size) + 1) * size;
        stop_min = (stop / size) * size;
        if (stop_min > start) {
          stop_min = stop_min - kEventTimeLists[types - 1];
        }
      }
    } else if (list_key > 0 || types == 1) {
      // Relax the requested bounds to fit the requested/only index.
      start = (start / size) * size;
      start_max = ((start_max / size) + 1) * size;
    }

    // (1) The first iteration will have 1 range (start to start_max=stop).
    // (2) Intermediate iterations will have 2 (start-start_max, stop-stop_min).
    // For each iteration the range collapses based on the coverage using
    // the first bin's start time and the last bin's stop time.
    // (3) The last iteration's range includes relaxed bounds outside the
    // requested start to stop range.
    std::vector<std::string> all_bins, bins, expirations;
    boost::split(all_bins, time_list, boost::is_any_of(","));
    for (const auto& bin : all_bins) {
      // Bins are identified by the binning size step.
      auto step = timeFromRecord(bin);
      // Check if size * step -> size * (step + 1) is within a range.
      int bin_start = size * step, bin_stop = size * (step + 1);
      if (expire_events_ && expire_time_ > 0) {
        if (bin_stop <= expire_time_) {
          expirations.push_back(bin);
        } else if (bin_start < expire_time_) {
          expireRecords(list_type, bin, false);
        }
      }

      if (bin_start >= start && bin_stop <= start_max) {
        bins.push_back(bin);
      } else if ((bin_start >= stop_min && bin_stop <= stop) || stop == 0) {
        bins.push_back(bin);
      }
    }

    // Rewrite the index lists and delete each expired item.
    if (expirations.size() > 0) {
      expireIndexes(list_type, all_bins, expirations);
    }

    if (bins.size() != 0) {
      // If more precision was achieved though this list's binning.
      local_start = timeFromRecord(bins.front()) * size;
      start_max = (local_start < start_max) ? local_start : start_max;
      local_stop = (timeFromRecord(bins.back()) + 1) * size;
      stop_min = (local_stop < stop_min) ? local_stop : stop_min;
    }

    for (const auto& bin : bins) {
      indexes.insert(list_type + "." + bin);
    }

    if (start == start_max && stop == stop_min) {
      break;
    }
  }

  // Update the new time that events expire to now - expiry.
  return indexes;
}

void EventSubscriberPlugin::expireRecords(const std::string& list_type,
                                          const std::string& index,
                                          bool all) {
  auto db = DBHandle::getInstance();
  auto record_key = "records." + dbNamespace();
  auto data_key = "data." + dbNamespace();

  // If the expirations is not removing all records, rewrite the persisting.
  std::vector<std::string> persisting_records;
  // Request all records within this list-size + bin offset.
  auto expired_records = getRecords({list_type + "." + index});
  for (const auto& record : expired_records) {
    if (all) {
      db->Delete(kEvents, data_key + "." + record.first);
    } else if (record.second > expire_time_) {
      persisting_records.push_back(record.first + ":" +
                                   std::to_string(record.second));
    }
  }

  // Either drop or overwrite the record list.
  if (all) {
    db->Delete(kEvents, record_key + "." + list_type + "." + index);
  } else {
    auto new_records = boost::algorithm::join(persisting_records, ",");
    db->Put(kEvents, record_key + "." + list_type + "." + index, new_records);
  }
}

void EventSubscriberPlugin::expireIndexes(
    const std::string& list_type,
    const std::vector<std::string>& indexes,
    const std::vector<std::string>& expirations) {
  auto db = DBHandle::getInstance();
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
  db->Put(kEvents, index_key + "." + list_type, new_indexes);
}

std::vector<EventRecord> EventSubscriberPlugin::getRecords(
    const std::set<std::string>& indexes) {
  auto db = DBHandle::getInstance();
  auto record_key = "records." + dbNamespace();

  std::vector<EventRecord> records;
  for (const auto& index : indexes) {
    std::vector<std::string> bin_records;
    {
      std::string record_value;
      if (!db->Get(kEvents, record_key + "." + index, record_value).ok()) {
        return records;
      }

      if (record_value.length() == 0) {
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
      EventTime time = timeFromRecord(*(++bin_it));
      records.push_back(std::make_pair(eid, time));
    }
  }

  return std::move(records);
}

Status EventSubscriberPlugin::recordEvent(EventID& eid, EventTime time) {
  Status status;
  auto db = DBHandle::getInstance();
  std::string time_value = boost::lexical_cast<std::string>(time);

  // The record is identified by the event type then module name.
  std::string index_key = "indexes." + dbNamespace();
  std::string record_key = "records." + dbNamespace();
  // The list key includes the list type (bin size) and the list ID (bin).
  std::string list_key;
  std::string list_id;

  for (auto time_list : kEventTimeLists) {
    // The list_id is the MOST-Specific key ID, the bin for this list.
    // If the event time was 13 and the time_list is 5 seconds, lid = 2.
    list_id = boost::lexical_cast<std::string>(time / time_list);
    // The list name identifies the 'type' of list.
    list_key = boost::lexical_cast<std::string>(time_list);
    // list_key = list_key + "." + list_id;

    {
      boost::lock_guard<boost::mutex> lock(event_record_lock_);
      // Append the record (eid, unix_time) to the list bin.
      std::string record_value;
      status = db->Get(
          kEvents, record_key + "." + list_key + "." + list_id, record_value);

      if (record_value.length() == 0) {
        // This is a new list_id for list_key, append the ID to the indirect
        // lookup for this list_key.
        std::string index_value;
        status = db->Get(kEvents, index_key + "." + list_key, index_value);
        if (index_value.length() == 0) {
          // A new index.
          index_value = list_id;
        } else {
          index_value += "," + list_id;
        }
        status = db->Put(kEvents, index_key + "." + list_key, index_value);
        record_value = eid + ":" + time_value;
      } else {
        // Tokenize a record using ',' and the EID/time using ':'.
        record_value += "," + eid + ":" + time_value;
      }
      status = db->Put(
          kEvents, record_key + "." + list_key + "." + list_id, record_value);
      if (!status.ok()) {
        LOG(ERROR) << "Could not put Event Record key: " << record_key << "."
                   << list_key << "." << list_id;
      }
    }
  }

  return Status(0, "OK");
}

EventID EventSubscriberPlugin::getEventID() {
  Status status;
  auto db = DBHandle::getInstance();
  // First get an event ID from the meta key.
  std::string eid_key = "eid." + dbNamespace();
  std::string last_eid_value;
  std::string eid_value;

  {
    boost::lock_guard<boost::mutex> lock(event_id_lock_);
    status = db->Get(kEvents, eid_key, last_eid_value);
    if (!status.ok()) {
      last_eid_value = "0";
    }

    size_t eid = boost::lexical_cast<size_t>(last_eid_value) + 1;
    eid_value = boost::lexical_cast<std::string>(eid);
    status = db->Put(kEvents, eid_key, eid_value);
  }

  if (!status.ok()) {
    return "0";
  }

  return eid_value;
}

QueryData EventSubscriberPlugin::get(EventTime start, EventTime stop) {
  QueryData results;
  Status status;

  std::shared_ptr<DBHandle> db = nullptr;
  try {
    db = DBHandle::getInstance();
  } catch (const std::runtime_error& e) {
    LOG(ERROR) << "Cannot retrieve subscriber results database is locked";
    return results;
  }

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

  // Select mapped_records using event_ids as keys.
  std::string data_value;
  for (const auto& record : mapped_records) {
    Row r;
    status = db->Get(kEvents, record, data_value);
    if (data_value.length() == 0) {
      // There is no record here, interesting error case.
      continue;
    }
    status = deserializeRowJSON(data_value, r);
    data_value.clear();
    if (status.ok()) {
      results.push_back(std::move(r));
    }
  }

  if (FLAGS_events_expiry > 0) {
    // Set the expire time to NOW - "configured lifetime".
    // Index retrieval will apply the constraints checking and auto-expire.
    expire_time_ = getUnixTime() - FLAGS_events_expiry;
  }
  return std::move(results);
}

Status EventSubscriberPlugin::add(Row& r, EventTime event_time) {
  std::shared_ptr<DBHandle> db = nullptr;
  try {
    db = DBHandle::getInstance();
  } catch (const std::runtime_error& e) {
    return Status(1, e.what());
  }

  // Get and increment the EID for this module.
  EventID eid = getEventID();
  // Without encouraging a missing event time, do not support a 0-time.
  r["time"] = std::to_string((event_time == 0) ? getUnixTime() : event_time);

  // Serialize and store the row data, for query-time retrieval.
  std::string data;
  auto status = serializeRowJSON(r, data);
  if (!status.ok()) {
    return status;
  }

  // Store the event data.
  std::string event_key = "data." + dbNamespace() + "." + eid;
  status = db->Put(kEvents, event_key, data);
  // Record the event in the indexing bins, using the index time.
  recordEvent(eid, event_time);
  return status;
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
      auto thread_ = std::make_shared<boost::thread>(
          boost::bind(&EventFactory::run, publisher.first));
      ef.threads_.push_back(thread_);
    }
  }
}

Status EventFactory::run(EventPublisherID& type_id) {
  auto& ef = EventFactory::getInstance();
  if (FLAGS_disable_events) {
    return Status(0, "Events disabled");
  }

  // An interesting take on an event dispatched entrypoint.
  // There is little introspection into the event type.
  // Assume it can either make use of an entrypoint poller/selector or
  // take care of async callback registrations in setUp/configure/run
  // only once and handle event queuing/firing in callbacks.
  EventPublisherRef publisher = ef.getEventPublisher(type_id);

  if (publisher == nullptr) {
    return Status(1, "Event publisher is missing");
  } else if (publisher->hasStarted()) {
    return Status(1, "Cannot restart an event publisher");
  }
  VLOG(1) << "Starting event publisher run loop: " + type_id;
  publisher->hasStarted(true);

  auto status = Status(0, "OK");
  while (!publisher->isEnding() && status.ok()) {
    // Can optionally implement a global cooloff latency here.
    status = publisher->run();
    publisher->restart_count_++;
    osquery::publisherSleep(EVENTS_COOLOFF);
  }
  // The runloop status is not reflective of the event type's.
  VLOG(1) << "Event publisher " << publisher->type()
          << " run loop terminated for reason: " << status.getMessage();
  // Publishers auto tear down when their run loop stops.
  publisher->tearDown();

  // Do not remove the publisher from the event factory.
  // If the event factory's `end` method was called these publishers will be
  // cleaned up after their thread context is removed; otherwise, a removed
  // thread context and failed publisher will remain available for stats.
  // ef.event_pubs_.erase(type_id);
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
  } catch (const std::bad_cast& e) {
    return Status(1, "Incorrect plugin");
  }

  if (specialized_pub == nullptr || specialized_pub.get() == nullptr) {
    return Status(0, "Invalid subscriber");
  }

  auto& ef = EventFactory::getInstance();
  auto type_id = specialized_pub->type();
  if (ef.event_pubs_.count(type_id) != 0) {
    // This is a duplicate event publisher.
    return Status(1, "Duplicate publisher type");
  }

  // Do not set up event publisher if events are disabled.
  ef.event_pubs_[type_id] = specialized_pub;
  if (!FLAGS_disable_events) {
    auto status = specialized_pub->setUp();
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
  } catch (const std::bad_cast& e) {
    return Status(1, "Incorrect plugin");
  }

  if (specialized_sub == nullptr || specialized_sub.get() == nullptr) {
    return Status(1, "Invalid subscriber");
  }

  // Let the module initialize any Subscriptions.
  auto status = Status(0, "OK");
  if (!FLAGS_disable_events) {
    status = specialized_sub->init();
  }

  auto& ef = EventFactory::getInstance();
  ef.event_subs_[specialized_sub->getName()] = specialized_sub;

  // Set state of subscriber.
  if (!status.ok()) {
    specialized_sub->state(SUBSCRIBER_FAILED);
    return Status(1, status.getMessage());
  } else {
    specialized_sub->state(SUBSCRIBER_RUNNING);
    return Status(0, "OK");
  }
}

Status EventFactory::addSubscription(EventPublisherID& type_id,
                                     EventSubscriberID& name_id,
                                     const SubscriptionContextRef& mc,
                                     EventCallback cb,
                                     void* user_data) {
  auto subscription = Subscription::create(name_id, mc, cb, user_data);
  return EventFactory::addSubscription(type_id, subscription);
}

Status EventFactory::addSubscription(EventPublisherID& type_id,
                                     const SubscriptionRef& subscription) {
  EventPublisherRef publisher = getInstance().getEventPublisher(type_id);
  if (publisher == nullptr) {
    return Status(1, "Unknown event publisher");
  }

  // The event factory is responsible for configuring the event types.
  auto status = publisher->addSubscription(subscription);
  if (!FLAGS_disable_events) {
    publisher->configure();
  }
  return status;
}

size_t EventFactory::numSubscriptions(EventPublisherID& type_id) {
  EventPublisherRef publisher;
  try {
    publisher = EventFactory::getInstance().getEventPublisher(type_id);
  } catch (std::out_of_range& e) {
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
      // If the run loop did run the tear down and erase will happen in the
      // event thread wrapper when isEnding is next checked.
      ef.event_pubs_.erase(type_id);
    } else {
      publisher->end();
    }
  }
  return Status(0, "OK");
}

std::vector<std::string> EventFactory::publisherTypes() {
  std::vector<std::string> types;
  for (const auto& publisher : getInstance().event_pubs_) {
    types.push_back(publisher.first);
  }
  return types;
}

std::vector<std::string> EventFactory::subscriberNames() {
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

  // A small cool off helps OS API event publisher flushing.
  if (!FLAGS_disable_events) {
    ::usleep(400);
    ef.threads_.clear();
  }

  // Threads may still be executing, when they finish, release publishers.
  ef.event_pubs_.clear();
}

void attachEvents() {
  const auto& publishers = Registry::all("event_publisher");
  for (const auto& publisher : publishers) {
    EventFactory::registerEventPublisher(publisher.second);
  }

  const auto& subscribers = Registry::all("event_subscriber");
  for (const auto& subscriber : subscribers) {
    auto status = EventFactory::registerEventSubscriber(subscriber.second);
    if (!status.ok()) {
      LOG(ERROR) << "Error registering subscriber: " << status.getMessage();
    }
  }
}
}
