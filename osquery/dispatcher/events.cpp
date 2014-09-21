// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/events.h"
#include "osquery/dispatcher.h"

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "osquery/core/conversions.h"

namespace osquery {

// This is a default fire method that does not evaluate status.
// There are no specific defaults in the event context (just an ID count).
void EventType::fire() {
  EventID event_id = next_id++;
  EventTime event_time = 0;

  auto it = monitors.begin();
  auto context = boost::make_shared<EventContext>();
  for (; it != monitors.end(); it++) {
    auto callback = (*it)->callback;
    if (callback != nullptr) {
      callback(event_id, event_time, context);
    }
  }
}

// There's no reason for the event factory to keep multiple instances.
boost::shared_ptr<EventFactory> EventFactory::get() {
  static auto q = boost::shared_ptr<EventFactory>(new EventFactory());
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

  Status status;

  // The event factory is responsible for configuring the event types.
  status = event_type->addMonitor(monitor);
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

boost::shared_ptr<EventType> EventFactory::getEventType(EventTypeID type_id) {
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
