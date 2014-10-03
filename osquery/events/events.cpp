// Copyright 2004-present Facebook. All Rights Reserved.

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/core/conversions.h"
#include "osquery/events.h"
#include "osquery/dispatcher.h"

namespace osquery {

const std::vector<size_t> kEventTimeLists = {1 * 60, // 1 minute
                                             1 * 60 * 60, // 1 hour
                                             12 * 60 * 60, // half-day
};

void EventPublisher::fire(const EventContextRef ec, EventTime time) {
  EventContextID ec_id;

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
      ec->time = time;
    }

    // Set the optional string-verion of the time for DB columns.
    ec->time_string = boost::lexical_cast<std::string>(ec->time);
  }

  for (const auto& monitor : monitors_) {
    auto callback = monitor->callback;
    if (shouldFire(monitor->context, ec) && callback != nullptr) {
      callback(ec, false);
    } else {
    }
  }
}

bool EventPublisher::shouldFire(const MonitorContextRef mc,
                           const EventContextRef ec) {
  return true;
}

Status EventPublisher::run() {
  // Runloops/entrypoints are ONLY implemented if needed.
  return Status(1, "No runloop required");
}

std::vector<EventRecord> EventSubscriber::getRecords(EventTime start,
                                                 EventTime stop) {
  Status status;
  std::vector<EventRecord> records;
  auto db = DBHandle::getInstance();

  std::string index_key = "indexes." + dbNamespace();
  std::string record_key = "records." + dbNamespace();

  // For now, cheat and use the first list type.
  std::string list_key = boost::lexical_cast<std::string>(kEventTimeLists[0]);
  std::string index_value;

  // Get all bins for this list type.
  status = db->Get(kEvents, index_key + "." + list_key, index_value);
  if (index_value.length() == 0) {
    // There are no events in this time range.
    return records;
  }
  // Tokenize the value into our bins of the list type.
  std::vector<std::string> lists;
  boost::split(lists, index_value, boost::is_any_of(","));
  std::string record_value;
  for (const auto& list_id : lists) {
    status = db->Get(
        kEvents, record_key + "." + list_key + "." + list_id, record_value);
    if (record_value.length() == 0) {
      // There are actually no events in this bin, interesting error case.
      continue;
    }
    std::vector<std::string> bin_records;
    boost::split(bin_records, record_value, boost::is_any_of(",:"));
    auto bin_it = bin_records.begin();
    for (; bin_it != bin_records.end(); bin_it++) {
      std::string eid = *bin_it;
      EventTime time = boost::lexical_cast<EventTime>(*(++bin_it));
      records.push_back(std::make_pair(eid, time));
    }
  }

  // Now all the event_ids/event_times within the binned range exist.
  // Select further on the EXACT time range.

  return records;
}

Status EventSubscriber::recordEvent(EventID eid, EventTime time) {
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

EventID EventSubscriber::getEventID() {
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

QueryData EventSubscriber::get(EventTime start, EventTime stop) {
  QueryData results;
  Status status;
  auto db = DBHandle::getInstance();

  // Get the records for this time range.
  auto records = getRecords(start, stop);

  std::string events_key = "data." + dbNamespace();

  // Select records using event_ids as keys.
  std::string data_value;
  for (const auto& record : records) {
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

Status EventSubscriber::add(const Row& r, EventTime time) {
  Status status;
  auto db = DBHandle::getInstance();

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
  for (const auto& eventtype : EventFactory::getInstance().event_pubs_) {
    auto thread_ = std::make_shared<boost::thread>(
        boost::bind(&EventFactory::run, eventtype.first));
    ef.threads_.push_back(thread_);
  }
}

Status EventFactory::run(EventPublisherID type_id) {
  // An interesting take on an event dispatched entrypoint.
  // There is little introspection into the event type.
  // Assume it can either make use of an entrypoint poller/selector or
  // take care of async callback registrations in setUp/configure/run
  // only once and handle event queueing/firing in callbacks.
  auto event_pub = EventFactory::getInstance().getEventPublisher(type_id);
  if (event_pub == nullptr) {
    return Status(1, "No Event Type");
  }

  Status status = Status(0, "OK");
  while (!EventFactory::getInstance().ending_ && status.ok()) {
    // Can optionally implement a global cooloff latency here.
    status = event_pub->run();
  }

  // The runloop status is not reflective of the event type's.
  return Status(0, "OK");
}

void EventFactory::end(bool should_end) {
  EventFactory::getInstance().ending_ = should_end;
  // Join on the thread group.
  ::usleep(400);
}

// There's no reason for the event factory to keep multiple instances.
EventFactory& EventFactory::getInstance() {
  static EventFactory ef;
  return ef;
}

Status EventFactory::registerEventPublisher(const EventPublisherRef event_pub) {
  auto& ef = EventFactory::getInstance();
  auto type_id = event_pub->type();

  if (ef.getEventPublisher(type_id) != nullptr) {
    // This is a duplicate type id?
    return Status(1, "Duplicate Event Type");
  }

  ef.event_pubs_[type_id] = event_pub;
  event_pub->setUp();
  return Status(0, "OK");
}

Status EventFactory::registerEventSubscriber(const EventSubscriberRef event_module) {
  auto& ef = EventFactory::getInstance();
  // Let the module initialize any Monitors.
  event_module->init();
  ef.event_modules_.push_back(event_module);
  return Status(0, "OK");
}

Status EventFactory::addMonitor(EventPublisherID type_id, const MonitorRef monitor) {
  auto event_pub = EventFactory::getInstance().getEventPublisher(type_id);
  if (event_pub == nullptr) {
    // Cannot create a Monitor for a missing type_id.
    return Status(1, "No Event Type");
  }

  // The event factory is responsible for configuring the event types.
  auto status = event_pub->addMonitor(monitor);
  event_pub->configure();
  return status;
}

Status EventFactory::addMonitor(EventPublisherID type_id,
                                const MonitorContextRef mc,
                                EventCallback cb) {
  auto monitor = Monitor::create(mc, cb);
  return EventFactory::addMonitor(type_id, monitor);
}

size_t EventFactory::numMonitors(EventPublisherID type_id) {
  const auto& event_pub = EventFactory::getInstance().getEventPublisher(type_id);
  if (event_pub != nullptr) {
    return event_pub->numMonitors();
  }
  return 0;
}

std::shared_ptr<EventPublisher> EventFactory::getEventPublisher(EventPublisherID type_id) {
  auto& ef = EventFactory::getInstance();
  const auto& it = ef.event_pubs_.find(type_id);
  if (it != ef.event_pubs_.end()) {
    return ef.event_pubs_[type_id];
  }
  return nullptr;
}

Status EventFactory::deregisterEventPublisher(const EventPublisherRef event_pub) {
  return EventFactory::deregisterEventPublisher(event_pub->type());
}

Status EventFactory::deregisterEventPublisher(EventPublisherID type_id) {
  auto& ef = EventFactory::getInstance();
  const auto& it = ef.event_pubs_.find(type_id);
  if (it == ef.event_pubs_.end()) {
    return Status(1, "No Event Type registered");
  }

  ef.event_pubs_[type_id]->tearDown();
  ef.event_pubs_.erase(it);
  return Status(0, "OK");
}

Status EventFactory::deregisterEventPublishers() {
  auto& ef = EventFactory::getInstance();
  auto it = ef.event_pubs_.begin();
  for (; it != ef.event_pubs_.end(); it++) {
    it->second->tearDown();
  }

  ef.event_pubs_.erase(ef.event_pubs_.begin(), ef.event_pubs_.end());
  return Status(0, "OK");
}
}

namespace osquery {
namespace registries {
void faucet(EventPublishers ets, EventSubscribers ems) {
  auto& ef = osquery::EventFactory::getInstance();
  for (const auto& event_pub : ets) {
    ef.registerEventPublisher(event_pub.second);
  }

  for (const auto& event_module : ems) {
    ef.registerEventSubscriber(event_module.second);
  }
}
}
}
