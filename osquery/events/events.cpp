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
#include <osquery/dispatcher.h>
#include <osquery/events.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/core/conversions.h"

namespace osquery {

DEFINE_osquery_flag(bool,
                    event_pubsub,
                    true,
                    "Use (enable) the osquery eventing pub/sub.");

DEFINE_osquery_flag(int32,
                    event_pubsub_expiry,
                    86000,
                    "Expire (remove) recorded events after a timeout.");

const std::vector<size_t> kEventTimeLists = {
    1 * 60 * 60, // 1 hour
    1 * 60, // 1 minute
    10, // 10 seconds
};

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

    // Set the optional string-verion of the time for DB columns.
    ec->time_string = boost::lexical_cast<std::string>(ec->time);
  }

  for (const auto& subscription : subscriptions_) {
    fireCallback(subscription, ec);
  }
}

std::vector<std::string> EventSubscriberPlugin::getIndexes(EventTime start,
                                                           EventTime stop,
                                                           int list_key) {
  auto db = DBHandle::getInstance();
  auto index_key = "indexes." + dbNamespace();
  std::vector<std::string> indexes;

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
    // (2) Itermediate iterations will have 2 (start-start_max, stop-stop_min).
    // For each iteration the range collapses based on the coverage using
    // the first bin's start time and the last bin's stop time.
    // (3) The last iteration's range includes relaxed bounds outside the
    // requested start to stop range.
    std::vector<std::string> all_bins, bins, expirations;
    boost::split(all_bins, time_list, boost::is_any_of(","));
    for (const auto& bin : all_bins) {
      // Bins are identified by the binning size step.
      auto step = boost::lexical_cast<EventTime>(bin);
      // Check if size * step -> size * (step + 1) is within a range.
      int bin_start = size * step, bin_stop = size * (step + 1);
      if (expire_events_ && step * size < expire_time_) {
        expirations.push_back(list_type + "." + bin);
      } else if (bin_start >= start && bin_stop <= start_max) {
        bins.push_back(bin);
      } else if ((bin_start >= stop_min && bin_stop <= stop) || stop == 0) {
        bins.push_back(bin);
      }
    }

    expireIndexes(list_type, all_bins, expirations);
    if (bins.size() != 0) {
      // If more percision was acheived though this list's binning.
      local_start = boost::lexical_cast<EventTime>(bins.front()) * size;
      start_max = (local_start < start_max) ? local_start : start_max;
      local_stop = (boost::lexical_cast<EventTime>(bins.back()) + 1) * size;
      stop_min = (local_stop < stop_min) ? local_stop : stop_min;
    }

    for (const auto& bin : bins) {
      indexes.push_back(list_type + "." + bin);
    }

    if (start == start_max && stop == stop_min) {
      break;
    }
  }

  // Update the new time that events expire to now - expiry.
  return indexes;
}

Status EventSubscriberPlugin::expireIndexes(
    const std::string& list_type,
    const std::vector<std::string>& indexes,
    const std::vector<std::string>& expirations) {
  auto db = DBHandle::getInstance();
  auto index_key = "indexes." + dbNamespace();
  auto record_key = "records." + dbNamespace();
  auto data_key = "data." + dbNamespace();

  // Get the records list for the soon-to-be expired records.
  std::vector<std::string> record_indexes;
  for (const auto& bin : expirations) {
    record_indexes.push_back(list_type + "." + bin);
  }
  auto expired_records = getRecords(record_indexes);

  // Remove the records using the list of expired indexes.
  std::vector<std::string> persisting_indexes = indexes;
  for (const auto& bin : expirations) {
    db->Delete(kEvents, record_key + "." + list_type + "." + bin);
    persisting_indexes.erase(
        std::remove(persisting_indexes.begin(), persisting_indexes.end(), bin),
        persisting_indexes.end());
  }

  // Update the list of indexes with the non-expired indexes.
  auto new_indexes = boost::algorithm::join(persisting_indexes, ",");
  db->Put(kEvents, index_key + "." + list_type, new_indexes);

  // Delete record events.
  for (const auto& record : expired_records) {
    db->Delete(kEvents, data_key + "." + record.first);
  }

  return Status(0, "OK");
}

std::vector<EventRecord> EventSubscriberPlugin::getRecords(
    const std::vector<std::string>& indexes) {
  auto db = DBHandle::getInstance();
  auto record_key = "records." + dbNamespace();
  std::vector<EventRecord> records;

  for (const auto& index : indexes) {
    std::string record_value;
    if (!db->Get(kEvents, record_key + "." + index, record_value).ok()) {
      return records;
    }

    if (record_value.length() == 0) {
      // There are actually no events in this bin, interesting error case.
      continue;
    }

    // Each list is tokenized into a record=event_id:time.
    std::vector<std::string> bin_records;
    boost::split(bin_records, record_value, boost::is_any_of(",:"));
    auto bin_it = bin_records.begin();
    for (; bin_it != bin_records.end(); bin_it++) {
      std::string eid = *bin_it;
      EventTime time = boost::lexical_cast<EventTime>(*(++bin_it));
      records.push_back(std::make_pair(eid, time));
    }
  }

  return records;
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

  std::shared_ptr<DBHandle> db;
  try {
    db = DBHandle::getInstance();
  } catch (const std::runtime_error& e) {
    LOG(ERROR) << "Cannot retrieve subscriber results database is locked";
    return results;
  }

  // Get the records for this time range.
  auto indexes = getIndexes(start, stop);
  auto records = getRecords(indexes);

  std::vector<EventRecord> mapped_records;
  for (const auto& record : records) {
    if (record.second >= start && (record.second <= stop || stop == 0)) {
      mapped_records.push_back(record);
    }
  }

  std::string events_key = "data." + dbNamespace();

  // Select mapped_records using event_ids as keys.
  std::string data_value;
  for (const auto& record : mapped_records) {
    Row r;
    status = db->Get(kEvents, events_key + "." + record.first, data_value);
    if (data_value.length() == 0) {
      // THere is no record here, interesting error case.
      continue;
    }
    status = deserializeRowJSON(data_value, r);
    if (status.ok()) {
      results.push_back(r);
    }
  }
  return results;
}

Status EventSubscriberPlugin::add(const Row& r, EventTime time) {
  Status status;

  std::shared_ptr<DBHandle> db;
  try {
    db = DBHandle::getInstance();
  } catch (const std::runtime_error& e) {
    return Status(1, e.what());
  }

  // Get and increment the EID for this module.
  EventID eid = getEventID();

  std::string event_key = "data." + dbNamespace() + "." + eid;
  std::string data;

  status = serializeRowJSON(r, data);
  if (!status.ok()) {
    return status;
  }

  // Store the event data.
  status = db->Put(kEvents, event_key, data);
  // Record the event in the indexing bins.
  recordEvent(eid, time);
  return status;
}

void EventFactory::delay() {
  auto& ef = EventFactory::getInstance();
  for (const auto& publisher : EventFactory::getInstance().event_pubs_) {
    auto thread_ = std::make_shared<boost::thread>(
        boost::bind(&EventFactory::run, publisher.first));
    ef.threads_.push_back(thread_);
  }
}

Status EventFactory::run(EventPublisherID& type_id) {
  // An interesting take on an event dispatched entrypoint.
  // There is little introspection into the event type.
  // Assume it can either make use of an entrypoint poller/selector or
  // take care of async callback registrations in setUp/configure/run
  // only once and handle event queueing/firing in callbacks.
  EventPublisherRef publisher;
  try {
    publisher = EventFactory::getInstance().getEventPublisher(type_id);
  }
  catch (std::out_of_range& e) {
    return Status(1, "No event type found");
  }

  VLOG(1) << "Starting event publisher runloop: " + type_id;
  publisher->hasStarted(true);

  auto status = Status(0, "OK");
  while (!publisher->isEnding() && status.ok()) {
    // Can optionally implement a global cooloff latency here.
    status = publisher->run();
    ::usleep(20);
  }

  // The runloop status is not reflective of the event type's.
  publisher->tearDown();
  VLOG(1) << "Event publisher " << publisher->type() << " runloop terminated";
  return Status(0, "OK");
}

// There's no reason for the event factory to keep multiple instances.
EventFactory& EventFactory::getInstance() {
  static EventFactory ef;
  return ef;
}

Status EventFactory::registerEventPublisher(const EventPublisherRef& pub) {
  auto& ef = EventFactory::getInstance();
  auto type_id = pub->type();

  if (ef.event_pubs_.count(type_id) != 0) {
    // This is a duplicate event publisher.
    return Status(1, "Cannot register duplicate publisher type.");
  }

  if (!pub->setUp().ok()) {
    // Only start event loop if setUp succeeds.
    return Status(1, "Event publisher setUp failed");
  }

  ef.event_pubs_[type_id] = pub;
  return Status(0, "OK");
}

Status EventFactory::registerEventSubscriber(
    const EventSubscriberRef& event_module) {
  auto& ef = EventFactory::getInstance();
  // Let the module initialize any Subscriptions.
  event_module->init();
  ef.event_subs_[event_module->name()] = event_module;
  return Status(0, "OK");
}

Status EventFactory::addSubscription(EventPublisherID& type_id,
                                     const SubscriptionContextRef& mc,
                                     EventCallback cb) {
  auto subscription = Subscription::create(mc, cb);
  return EventFactory::addSubscription(type_id, subscription);
}

Status EventFactory::addSubscription(EventPublisherID& type_id,
                                     const SubscriptionRef& subscription) {
  EventPublisherRef publisher;
  try {
    publisher = getInstance().getEventPublisher(type_id);
  }
  catch (std::out_of_range& e) {
    return Status(1, "No event type found");
  }

  // The event factory is responsible for configuring the event types.
  auto status = publisher->addSubscription(subscription);
  publisher->configure();
  return status;
}

size_t EventFactory::numSubscriptions(EventPublisherID& type_id) {
  EventPublisherRef publisher;
  try {
    publisher = EventFactory::getInstance().getEventPublisher(type_id);
  }
  catch (std::out_of_range& e) {
    return 0;
  }
  return publisher->numSubscriptions();
}

EventPublisherRef EventFactory::getEventPublisher(EventPublisherID& type_id) {
  if (getInstance().event_pubs_.count(type_id) == 0) {
    LOG(ERROR) << "Requested unknown event publisher: " + type_id;
  }
  return getInstance().event_pubs_.at(type_id);
}

EventSubscriberRef EventFactory::getEventSubscriber(
    EventSubscriberID& name_id) {
  if (getInstance().event_subs_.count(name_id) == 0) {
    LOG(ERROR) << "Requested unknown event subscriber: " + name_id;
  }
  return getInstance().event_subs_.at(name_id);
}

Status EventFactory::deregisterEventPublisher(const EventPublisherRef& pub) {
  return EventFactory::deregisterEventPublisher(pub->type());
}

Status EventFactory::deregisterEventPublisher(EventPublisherID& type_id) {
  auto& ef = EventFactory::getInstance();
  EventPublisherRef publisher;
  try {
    publisher = ef.getEventPublisher(type_id);
  }
  catch (std::out_of_range& e) {
    return Status(1, "No event publisher to deregister.");
  }

  publisher->isEnding(true);
  if (!publisher->hasStarted()) {
    // If a publisher's run loop was not started, call tearDown since
    // the setUp happened at publisher registration time.
    publisher->tearDown();
  }

  ef.event_pubs_.erase(type_id);
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

  ::usleep(400);
  ef.threads_.clear();
}

void attachEvents() {
  const auto& publishers = Registry::all("event_publisher");
  for (const auto& publisher : publishers) {
    EventFactory::registerEventPublisher(std::move(publisher.second));
  }

  const auto& subscribers = Registry::all("event_subscriber");
  for (const auto& subscriber : subscribers) {
    EventFactory::registerEventSubscriber(std::move(subscriber.second));
  }
}
}
