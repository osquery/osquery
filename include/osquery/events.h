// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <functional>
#include <memory>
#include <map>
#include <vector>

#include <boost/make_shared.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include <boost/thread/locks.hpp>
#include <boost/thread/mutex.hpp>

#include "osquery/status.h"
#include "osquery/database.h"

namespace osquery {

struct Monitor;
class EventType;

typedef const std::string EventTypeID;
typedef const std::string EventID;
typedef uint32_t EventContextID;
typedef uint32_t EventTime;

struct MonitorContext {};
struct EventContext {};

typedef boost::shared_ptr<Monitor> MonitorRef;
typedef boost::shared_ptr<EventType> EventTypeRef;
typedef boost::shared_ptr<MonitorContext> MonitorContextRef;
typedef boost::shared_ptr<EventContext> EventContextRef;

typedef std::function<Status(EventContextID, EventTime, EventContextRef)>
EventCallback;

/// An EventType must track every monitor added.
typedef std::vector<MonitorRef> MonitorVector;

/// The EventFactory tracks every EventType and the name it specifies.
typedef std::map<EventTypeID, EventTypeRef> EventTypeMap;

/// The set of search-time binned lookup tables.
extern const std::vector<size_t> kEventTimeLists;

// Instead of attempting fancy RTTI limitations, each derived EventType may
// choose to macro-define a getter for a custom EventContext/MonitorContext.
// This assumes each event will implement custom fields for monitoring
// and custom fields holding event-related data.
#define DECLARE_EVENTTYPE(TYPE, MONITOR, EVENT)                              \
 public:                                                                     \
  EventTypeID type() const { return #TYPE; }                                 \
  static boost::shared_ptr<EVENT> getEventContext(EventContextRef context) { \
    return boost::static_pointer_cast<EVENT>(context);                       \
  }                                                                          \
  static boost::shared_ptr<MONITOR> getMonitorContext(                       \
      MonitorContextRef context) {                                           \
    return boost::static_pointer_cast<MONITOR>(context);                     \
  }                                                                          \
  static boost::shared_ptr<EVENT> createEventContext() {                     \
    return boost::make_shared<EVENT>();                                      \
  }

/// Helper define for binding EventModule to an EventType.
#define DECLARE_EVENTMODULE(NAME, TYPE)                  \
 public:                                                 \
  static boost::shared_ptr<NAME> get() {                 \
    static auto q = boost::shared_ptr<NAME>(new NAME()); \
    return q;                                            \
  }                                                      \
                                                         \
 private:                                                \
  EventTypeID name() const { return #NAME; }             \
  EventTypeID type() const { return #TYPE; }

/// Helper to define a static callback into an EventModule.
#define DECLARE_CALLBACK(__NAME__, EVENT)                               \
 public:                                                                \
  static Status Event##__NAME__(                                        \
      EventContextID ec_id, EventTime time, const EventContextRef ec) { \
    auto ec_ = boost::static_pointer_cast<EVENT>(ec);                   \
    return get()->Module##__NAME__(ec_id, time, ec_);                   \
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

  virtual Status run();

  virtual Status addMonitor(const MonitorRef monitor) {
    monitors_.push_back(monitor);
    return Status(0, "OK");
  }

  size_t numMonitors() { return monitors_.size(); }
  size_t numEvents() { return next_ec_id_; }

  EventType() : next_ec_id_(0) {};

  virtual EventTypeID type() const = 0;

 protected:
  /// The generic check loop to call monitor context callback methods.
  void fire(const EventContextRef ec, EventTime event_time = 0);
  /// Fire will check each monitor context againsts the event context.
  virtual bool shouldFire(const MonitorContextRef mc, const EventContextRef ec);

 protected:
  /// The EventType will keep track of Monitors that contain associated callins.
  MonitorVector monitors_;

  /// An Event ID is assigned by the EventType within the EventContext.
  /// This is not used to store EventData in the backing store.
  EventContextID next_ec_id_;

 private:
  boost::mutex ec_id_lock_;

 private:
  FRIEND_TEST(EventsTests, test_fire_event);
};

/**
 * @brief An interface binding monitors, event response, and table generation.
 *
 * Use the EventModule interface when adding event monitors and defining callin
 * functions. The EventCallback typedef is usually a member function for an
 * EventModule. The EventModule interface includes a very important 'Add' method
 * that abstracts the needed event to backing store interaction.
 *
 * Storing event data in the backing store must match a table spec for queries.
 * Small overheads exist that help query-time indexing and lookups.
 */
class EventModule {
 protected:
  /// Store an event for Table-access into the underlying backing store.
  Status Add(const osquery::Row& r, int event_time);

 private:
  /// Returns a new Event ID for this module, increments to the current EID.
  EventID getEventID();

  /// Records an added EventID/Event data.
  Status recordEvent(EventID eid, int event_time);

 protected:
  /// Single instance requirement for static callback facilities.
  EventModule() {}

  /// Database namespace definition methods.
  virtual EventTypeID type() const = 0;
  virtual EventTypeID name() const = 0;

 private:
  boost::mutex event_id_lock_;
  boost::mutex event_record_lock_;

 private:
  FRIEND_TEST(EventsDatabaseTests, test_event_module_id);
  FRIEND_TEST(EventsDatabaseTests, test_unique_event_module_id);
};

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

  static size_t numMonitors(EventTypeID type_id);
  static size_t numEventTypes() {
    return EventFactory::get()->event_types_.size();
  }

  // A watching context MUST deregister events.
  // EventType's assume they can hook/trampoline, which requires cleanup.
  static Status deregisterEventType(const EventTypeRef event_type);
  static Status deregisterEventType(EventTypeID type_id);
  static Status deregisterEventTypes();

  static EventTypeRef getEventType(EventTypeID);

 public:
  /// The dispatched event thread's entrypoint (if needed).
  static Status run(EventTypeID type_id);
  /// An initializer's entrypoint for spawning all event type run loops.
  static void delay();
  static void end(bool should_end = true);

 private:
  EventFactory() { ending_ = false; }

 private:
  /// Set ending to true to cause event type run loops to finish.
  bool ending_;
  EventTypeMap event_types_;
  std::vector<boost::shared_ptr<boost::thread> > threads_;
};
}
