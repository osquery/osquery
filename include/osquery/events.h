// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <functional>
#include <memory>
#include <map>
#include <vector>

#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>

#include "osquery/status.h"

namespace osquery {

struct Monitor;
class EventType;

typedef const std::string EventTypeID;
typedef uint32_t EventID;
typedef uint32_t EventTime;

struct MonitorContext {};
struct EventContext {};

typedef boost::shared_ptr<Monitor> MonitorRef;
typedef boost::shared_ptr<EventType> EventTypeRef;
typedef boost::shared_ptr<MonitorContext> MonitorContextRef;
typedef boost::shared_ptr<EventContext> EventContextRef;

typedef std::function<Status(EventID, EventTime, EventContextRef)>
    EventCallback;

// Instead of attempting fancy RTTI limitations, each derived EventType may
// choose to macro-define a getter for a custom EventContext/MonitorContext.
// This assumes each event will implement custom fields for monitoring
// and custom fields holding event-related data.
#define DECLARE_EVENTTYPE(TYPE, MONITOR, EVENT)                              \
 public:                                                                     \
  EventTypeID type() { return TYPE; }                                        \
  static boost::shared_ptr<EVENT> getEventContext(EventContextRef context) { \
    return boost::static_pointer_cast<EVENT>(context);                       \
  }                                                                          \
  static boost::shared_ptr<MONITOR> getMonitorContext(                       \
      MonitorContextRef context) {                                           \
    return boost::static_pointer_cast<MONITOR>(context);                     \
  }

/**
 * @brief An implementation monitor context used to configure/create a monitor.
 *
 * The monitor stuct is a helper/boiler-plate constructor for a context and
 * the caller's callback.
 */
struct Monitor {
 public:
  MonitorContextRef context;
  EventCallback callback;

  static MonitorRef create() { return boost::make_shared<Monitor>(); }

  static MonitorRef create(const MonitorContextRef mc, EventCallback ec = 0) {
    auto monitor = boost::make_shared<Monitor>();
    monitor->context = mc;
    monitor->callback = ec;
    return monitor;
  }
};

typedef std::vector<MonitorRef> MonitorVector;

/**
 * @brief Generate OS events of a type (FS, Network, Syscall, ioctl).
 *
 * A class of OS Events is abstracted into a type-class responsible for
 * remaining as agile as possible given a known-set of monitors using the
 * events.
 *
 * There are four actions an event generator will take, start, configure, stop,
 * and generate event. THe configure is a pseudo-start that may occur during
 * runtime.
 */
class EventType {
 public:
  virtual void configure() {}
  virtual void setUp() {}
  virtual void tearDown() {}

  virtual void fire();

  Status addMonitor(const MonitorRef monitor) {
    monitors.push_back(monitor);
    return Status(0, "OK");
  }

  size_t numMonitors() { return monitors.size(); }

  EventType(){};

  virtual EventTypeID type() = 0;

 protected:
  MonitorVector monitors;
  EventID next_id;
};

typedef std::map<EventTypeID, EventTypeRef> EventTypeMap;

/**
 * @brief A factory for associating event generators to event type IDs.
 *
 * This factory both registers new event types and the monitors that use them.
 * An event type is also a factor, the single event factory arbitates monitor
 * creatating and management for each associated event type.
 *
 * Since event types may be plugins, they are created using the factory.
 * Since monitors may be configured/disabled they are also factory-managed.
 */
class EventFactory {
 public:
  static boost::shared_ptr<EventFactory> get();

  template <typename T>
  static Status registerEventType() {
    auto event_type = boost::make_shared<T>();
    return EventFactory::registerEventType(event_type);
  }
  static Status registerEventType(const EventTypeRef event_type);

  static Status addMonitor(EventTypeID type_id, const MonitorRef monitor);
  static Status addMonitor(EventTypeID type_id,
                           const MonitorContextRef mc,
                           EventCallback callback = 0);

  static size_t numMonitors(EventTypeID);
  static size_t numEventTypes() {
    return EventFactory::get()->event_types_.size();
  }

  // A watching context MUST deregister events.
  // EventType's assume they can hook/trampoline, which requires cleanup.
  static Status deregisterEventType(const EventTypeRef event_type);
  static Status deregisterEventType(EventTypeID type_id);
  static Status deregisterEventTypes();

  static EventTypeRef getEventType(EventTypeID);

 private:
  EventFactory() {}

 private:
  EventTypeMap event_types_;
};
}
