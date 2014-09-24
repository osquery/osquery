// Copyright 2004-present Facebook. All Rights Reserved.

#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include "osquery/core/conversions.h"
#include "osquery/events.h"
#include "osquery/dispatcher.h"

namespace osquery {

const std::vector<size_t> kEventTimeLists = {
    1 * 60, // 1 minute
    1 * 60 * 60, // 1 hour
    12 * 60 * 60, // half-day
};

void EventType::fire(const EventContextRef ec, EventTime event_time) {
  EventContextID ec_id;

  {
    boost::lock_guard<boost::mutex> lock(ec_id_lock_);
    ec_id = next_ec_id_++;
  }

  for (const auto& monitor : monitors_) {
    auto callback = monitor->callback;
    if (shouldFire(monitor->context, ec) && callback != nullptr) {
      callback(ec_id, event_time, ec);
    }
  }
}

bool EventType::shouldFire(const MonitorContextRef mc,
                           const EventContextRef ec) {
  return true;
}

Status EventType::run() {
  // Runloops/entrypoints are ONLY implemented if needed.
  return Status(1, "No runloop required");
}

Status EventModule::recordEvent(EventID eid, int event_time) {
  Status status;
  auto db = DBHandle::getInstance();
  std::string time_value = boost::lexical_cast<std::string>(event_time);

  // The record is identified by the event type then module name.
  std::string record_key = "records." + type() + "." + name();
  // The list key includes the list type (bin size) and the list ID (bin).
  std::string list_key;
  std::string list_id;
  // This is an append operation, the record value is tokenized with this event.
  std::string record_value;

  for (auto time_list : kEventTimeLists) {
    // The list_id is the MOST-Specific key ID, the bin for this list.
    // If the event time was 13 and the time_list is 5 seconds, lid = 2.
    list_id = boost::lexical_cast<std::string>(event_time % time_list);
    // The list name identifies the 'type' of list.
    list_key = boost::lexical_cast<std::string>(time_list);
    list_key = record_key + "." + list_key + "." + list_id;

    {
      boost::lock_guard<boost::mutex> lock(event_record_lock_);
      // Append the record (eid, unix_time) to the list bin.
      status = db->Get(kEvents, list_key, record_value);

      if (record_value.length() == 0) {
        record_value = eid + ":" + time_value;
      } else {
        // Tokenize a record using ',' and the EID/time using ':'.
        record_value += "," + eid + ":" + time_value;
      }
      status = db->Put(kEvents, list_key, record_value);
      if (!status.ok()) {
        LOG(ERROR) << "Could not put Event Record key: " << list_key;
      }
    }
  }

  return Status(0, "OK");
}

EventID EventModule::getEventID() {
  Status status;
  auto db = DBHandle::getInstance();
  // First get an event ID from the meta key.
  std::string eid_key = "eid." + type() + "." + name();
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

Status EventModule::Add(const osquery::Row& r, int event_time) {
  Status status;
  auto db = DBHandle::getInstance();

  // Get and increment the EID for this module.
  EventID eid = getEventID();

  std::string event_key = "data." + type() + "." + name() + "." + eid;
  std::string data;

  status = osquery::serializeRowJSON(r, data);
  if (!status.ok()) {
    printf("could not serialize json\n");
    return status;
  }

  // Store the event data.
  status = db->Put(kEvents, event_key, data);
  // Record the event in the indexing bins.
  recordEvent(eid, event_time);
  return status;
}

void EventFactory::delay() {
  auto ef = EventFactory::get();
  for (const auto& eventtype : EventFactory::get()->event_types_) {
    auto thread_ = std::make_shared<boost::thread>(
        boost::bind(&EventFactory::run, eventtype.first));
    ef->threads_.push_back(thread_);
  }
}

Status EventFactory::run(EventTypeID type_id) {
  // An interesting take on an event dispatched entrypoint.
  // There is little introspection into the event type.
  // Assume it can either make use of an entrypoint poller/selector or
  // take care of async callback registrations in setUp/configure/run
  // only once and handle event queueing/firing in callbacks.
  auto event_type = EventFactory::get()->getEventType(type_id);
  if (event_type == nullptr) {
    return Status(1, "No Event Type");
  }

  Status status = Status(0, "OK");
  while (!EventFactory::get()->ending_ && status.ok()) {
    // Can optionally implement a global cooloff latency here.
    status = event_type->run();
  }

  // The runloop status is not reflective of the event type's.
  return Status(0, "OK");
}

void EventFactory::end(bool should_end) {
  EventFactory::get()->ending_ = should_end;
  // Join on the thread group.
}

// There's no reason for the event factory to keep multiple instances.
std::shared_ptr<EventFactory> EventFactory::get() {
  static auto q = std::shared_ptr<EventFactory>(new EventFactory());
  return q;
}

Status EventFactory::registerEventType(const EventTypeRef event_type) {
  EventTypeID type_id = event_type->type();
  auto ef = EventFactory::get();

  if (ef->getEventType(type_id) != nullptr) {
    // This is a duplicate type id?
    return Status(1, "Duplicate Event Type");
  }

  ef->event_types_[type_id] = event_type;
  event_type->setUp();
  return Status(0, "OK");
}

Status EventFactory::addMonitor(EventTypeID type_id, const MonitorRef monitor) {
  auto event_type = EventFactory::get()->getEventType(type_id);
  if (event_type == nullptr) {
    // Cannot create a Monitor for a missing type_id.
    return Status(1, "No Event Type");
  }

  // The event factory is responsible for configuring the event types.
  auto status = event_type->addMonitor(monitor);
  event_type->configure();
  return status;
}

Status EventFactory::addMonitor(EventTypeID type_id,
                                const MonitorContextRef mc,
                                EventCallback callback) {
  auto monitor = Monitor::create(mc, callback);
  return EventFactory::addMonitor(type_id, monitor);
}

size_t EventFactory::numMonitors(EventTypeID type_id) {
  const auto& event_type = EventFactory::get()->getEventType(type_id);
  if (event_type != nullptr) {
    return event_type->numMonitors();
  }
  return 0;
}

std::shared_ptr<EventType> EventFactory::getEventType(EventTypeID type_id) {
  const auto& ef = EventFactory::get();
  const auto& it = ef->event_types_.find(type_id);
  if (it != ef->event_types_.end()) {
    return ef->event_types_[type_id];
  }
  return nullptr;
}

Status EventFactory::deregisterEventType(const EventTypeRef event_type) {
  return EventFactory::deregisterEventType(event_type->type());
}

Status EventFactory::deregisterEventType(EventTypeID type_id) {
  auto ef = EventFactory::get();
  const auto& it = ef->event_types_.find(type_id);
  if (it == ef->event_types_.end()) {
    return Status(1, "No Event Type registered");
  }

  ef->event_types_[type_id]->tearDown();
  ef->event_types_.erase(it);
  return Status(0, "OK");
}

Status EventFactory::deregisterEventTypes() {
  auto ef = EventFactory::get();
  auto it = ef->event_types_.begin();
  for (; it != ef->event_types_.end(); it++) {
    it->second->tearDown();
  }

  ef->event_types_.erase(ef->event_types_.begin(), ef->event_types_.end());
  return Status(0, "OK");
}
}
