// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <functional>
#include <memory>
#include <map>
#include <vector>

#include <boost/make_shared.hpp>
#include <boost/thread.hpp>
#include <boost/thread/locks.hpp>
#include <boost/thread/mutex.hpp>

#include "osquery/status.h"
#include "osquery/database.h"
#include "osquery/registry.h"

namespace osquery {

struct Monitor;
class EventType;
class EventModule;

typedef const std::string EventTypeID;
typedef const std::string EventID;
typedef uint32_t EventContextID;
typedef uint32_t EventTime;
typedef std::pair<EventID, EventTime> EventRecord;

/**
 * @brief An EventType will define a MonitorContext for EventModule%s to use.
 *
 * Most EventType%s will reqire specific information for interacting with an OS
 * to receive events. The MonitorContext contains information the EventType will
 * use to register OS API callbacks, create monitoring/listening handles, etc.
 *
 * Linux `inotify` should implement a MonitorContext that monitors filesystem
 * events based on a filesystem path. `libpcap` will monitor on networking
 * protocols at various stacks. Process creation may monitor on process name,
 * parent pid, etc.
 */
struct MonitorContext {};

/**
 * @brief An EventModule EventCallback method will receive an EventContext.
 *
 * The EventContext contains the event-related data supplied by an EventType
 * when the event occures. If a monitoring EventModule is should be called
 * for the event the EventModule%'s EventCallback is passed an EventContext.
 */
struct EventContext {
  /// An unique counting ID specific to the EventType%'s fired events.
  EventContextID id;
  /// The time the event occured.
  EventTime time;
  /// The string representation of the time, often used for indexing.
  std::string time_string;
};

typedef std::shared_ptr<Monitor> MonitorRef;
typedef std::shared_ptr<EventType> EventTypeRef;
typedef std::shared_ptr<MonitorContext> MonitorContextRef;
typedef std::shared_ptr<EventContext> EventContextRef;
typedef std::shared_ptr<EventModule> EventModuleRef;

typedef std::function<Status(EventContextRef, bool)> EventCallback;

/// An EventType must track every monitor added.
typedef std::vector<MonitorRef> MonitorVector;

/// The EventFactory tracks every EventType and the name it specifies.
typedef std::map<EventTypeID, EventTypeRef> EventTypeMap;

/// The set of search-time binned lookup tables.
extern const std::vector<size_t> kEventTimeLists;

/**
 * @brief Helper type casting methods for EventType classes.
 *
 * A new osquery EventType should subclass EventType and use the following:
 *
 * @code{.cpp}
 *   #include "osquery/events.h"
 *
 *   class MyEventType: public EventType {
 *     DECLARE_EVENTTYPE(MyEventType, MyMonitorContext, MyEventContext);
 *   }
 * @endcode
 *
 * This assumes new EventType%s will always include a custom MonitorContext
 * and EventContext. In the above example MyMonitorContext allows EventModule%s
 * to downselect or customize what events to handle. And MyEventContext includes
 * fields specific to the new EventType.
 */
#define DECLARE_EVENTTYPE(TYPE, MONITOR, EVENT)                            \
 public:                                                                   \
  EventTypeID type() const { return #TYPE; }                               \
  bool shouldFire(const MonitorContextRef mc, const EventContextRef ec) {  \
    if (#MONITOR == "MonitorContext" && #EVENT == "EventContext")          \
      return true;                                                         \
    return shouldFire(getMonitorContext(mc), getEventContext(ec));         \
  }                                                                        \
  static std::shared_ptr<EVENT> getEventContext(EventContextRef context) { \
    return std::static_pointer_cast<EVENT>(context);                       \
  }                                                                        \
  static std::shared_ptr<MONITOR> getMonitorContext(                       \
      MonitorContextRef context) {                                         \
    return std::static_pointer_cast<MONITOR>(context);                     \
  }                                                                        \
  static std::shared_ptr<EVENT> createEventContext() {                     \
    return std::make_shared<EVENT>();                                      \
  }                                                                        \
  static std::shared_ptr<MONITOR> createMonitorContext() {                 \
    return std::make_shared<MONITOR>();                                    \
  }

/**
 * @brief Required getter and namespace helper methods for EventModule%s.
 *
 * A new osquery `EventModule` should subclass EventModule with the following:
 *
 * @code{.cpp}
 *   #include "osquery/events.h"
 *
 *   class MyEventModule: public EventModule {
 *     DECLARE_EVENTMODULE(MyEventModule, MyEventType);
 *   }
 * @endcode
 *
 * EventModule%s should be specific to an EventType.
 */
#define DECLARE_EVENTMODULE(NAME, TYPE)                \
 public:                                               \
  static std::shared_ptr<NAME> getInstance() {         \
    static auto q = std::shared_ptr<NAME>(new NAME()); \
    return q;                                          \
  }                                                    \
  static QueryData genTable() __attribute__((used)) {  \
    return getInstance()->get(0, 0);                   \
  }                                                    \
                                                       \
 private:                                              \
  EventTypeID name() const { return #NAME; }           \
  EventTypeID type() const { return #TYPE; }           \
  NAME() {}

/**
 * @brief Required callin EventModule method declaration helper.
 *
 * An EventModule will include 1 or more EventCallback methods. Consider the
 * following flow: (1) Event occurs, (2) EventCallback is called with the
 * event details, (3) details logged, (4) details are queried.
 *
 * The above logic can be supplied in a class-like namespace with static
 * callin/callback functions:
 *
 * @code{.cpp}
 *   #include "osquery/events.h"
 *
 *   class MyEventModule: public EventModule {
 *     DECLARE_EVENTMODULE(MyEventModule, MyEventType);
 *     DECLARE_CALLBACK(MyCallback, MyEventContext)
 *
 *     Status ModuleMyCallback(EventContextID, EventTime, MyEventContext);
 *   }
 * @endcode
 *
 * And then somewhere else in code the callback can be registered:
 *
 * @code{.cpp}
 *   EventFactory::addMonitor("MyEventType", my_monitor_context,
 *                            MyEventModule::MyCallback);
 * @endcode
 *
 * The binding from static method, function pointer, and EventModule
 * instance boilerplate code is added automatically.
 * Note: The macro will append `Module` to `MyCallback`.
 */
#define DECLARE_CALLBACK(NAME, EVENT)                                  \
 public:                                                               \
  static Status Event##NAME(const EventContextRef ec, bool reserved) { \
    auto ec_ = std::static_pointer_cast<EVENT>(ec);                    \
    return getInstance()->NAME(ec_);                                   \
  }                                                                    \
                                                                       \
 private:                                                              \
  void BindTo##NAME(const MonitorContextRef mc) {                      \
    EventFactory::addMonitor(type(), mc, Event##NAME);                 \
  }

/**
 * @brief Bind a monitor context to a declared EventCallback for this module.
 *
 * Binding refers to the association of a callback for this EventModule to
 * a configured MonitorContext. Under the hood "binding" creates a factory
 * Monitor for the EventType used by the EventModule. Such that when an event
 * of the EventType is fired, if the event details match the specifics of the
 * MonitorContext the EventMonitor%'s EventCallback will be called.
 *
 * @code{.cpp}
 *   #include "osquery/events.h"
 *
 *   class MyEventModule: public EventModule {
 *     DECLARE_EVENTMODULE(MyEventModule, MyEventType);
 *     DECLARE_CALLBACK(MyCallback, MyEventContext);
 *
 *    public:
 *     void init() {
 *       auto mc = MyEventType::createMonitorContext();
 *       mc->requirement = "SOME_SPECIFIC_DETAIL";
 *       BIND_CALLBACK(MyCallback, mc);
 *     }
 *     Status MyCallback(const MyEventContextRef ec) {}
 *   }
 * @endcode
 *
 * The symbol `MyCallback` must match in `DECLARE_CALLBACK`, `BIND_CALLBACK` and
 * as a member of this EventModule.
 *
 * @param NAME The symbol for the EventCallback method used in DECLARE_CALLBACK.
 * @param MC The MonitorContext to bind.
 */
#define BIND_CALLBACK(NAME, MC) \
  EventFactory::addMonitor(type(), MC, Event##NAME);

/**
 * @brief A Monitor is used to configure an EventType and bind a callback.
 *
 * A Monitor is the input to an EventType when the EventType decides on
 * the scope and details of the events it watches and generates. An example
 * includes a filesystem change event. A monitor would include a path with
 * optional recursion and attribute selectors as well as a callback function
 * to fire when an event for that path and selector occurs.
 *
 * A Monitor also functions to greatly scope an EventType%'s work.
 * Using the same filesystem example and the Linux inotify subsystem a Monitor
 * limits the number of inode watches to only those requested by appropriate
 * EventModule%s.
 * Note: EventModule%s and Monitors can be configured by the osquery user.
 *
 * Monitors are usually created with EventFactory members:
 *
 * @code{.cpp}
 *   EventFactory::addMonitor("MyEventType", my_monitor_context);
 * @endcode
 */
struct Monitor {
 public:
  /// An EventType%-specific MonitorContext.
  MonitorContextRef context;
  /// An EventMonitor member EventCallback method.
  EventCallback callback;

  static MonitorRef create() { return std::make_shared<Monitor>(); }

  static MonitorRef create(const MonitorContextRef mc, EventCallback ec = 0) {
    auto monitor = std::make_shared<Monitor>();
    monitor->context = mc;
    monitor->callback = ec;
    return monitor;
  }
};

/**
 * @brief Generate OS events of a type (FS, Network, Syscall, ioctl).
 *
 * A 'class' of OS events is abstracted into an EventType responsible for
 * remaining as agile as possible given a known-set of monitors.
 *
 * The lifecycle of an EventType may include, `setUp`, `configure`, `run`,
 * `tearDown`, and `fire`. `setUp` and `tearDown` happen when osquery starts and
 * stops either as a daemon or interactive shell. `configure` is a pseudo-start
 * called every time a Monitor is added. EventType%s can adjust their
 * scope/agility specific to each added monitor by overriding `addMonitor`,
 * and or globally in `configure`.
 *
 * Not all EventType%s leverage pure async OS APIs, and most will require a run
 * loop either polling with a timeout on a descriptor or for a change. When
 * osquery initializes the EventFactory will optionally create a thread for each
 * EventType using `run` as the thread's entrypoint. This is called in a
 * within-thread loop where returning a FAILED status ends the run loop and
 * shuts down the thread.
 *
 * To opt-out of polling in a thread consider the following run implementation:
 *
 * @code{.cpp}
 *   Status run() { return Status(1, "Not Implemented") }
 * @endcode
 *
 * The final lifecycle component, `fire` will iterate over the EventType
 * Monitor%s and call `shouldFire` for each, using the EventContext fired.
 * The `shouldFire` method should check the monitor-specific selectors and only
 * call the Monitor%'s callback function is the EventContext (thus event)
 * matches.
 */
class EventType {
 public:
  /**
   * @brief A new Monitor was added, potentially change state based on all
   * monitors for this EventType.
   *
   * `configure` allows the EventType to optimize on the state of all monitors.
   * An example is Linux `inotify` where multiple EventMonitor%s will monitor
   * identical paths, e.g., /etc for config changes. Since Linux `inotify` has
   * a monitor limit, `configure` can depup paths.
   */
  virtual void configure() {}

  /**
   * @brief Perform handle opening, OS API callback registration.
   *
   * `setUp` is the event framework's EventType constructor equivilent. When
   * `setUp` is called the EventType is running in a dedicated thread and may
   * manage/allocate/wait for resources.
   */
  virtual void setUp() {}

  /**
   * @brief Perform handle closing, resource cleanup.
   *
   * osquery is about to end, the EventType should close handle descriptors
   * unblock resources, and prepare to exit.
   */
  virtual void tearDown() {}

  /**
   * @brief Implement a step of an optional run loop.
   *
   * @return A SUCCESS status will immediately call `run` again. A FAILED status
   * will exit the run loop and the thread.
   */
  virtual Status run();

  /**
   * @brief A new EventModule is monitoring events of this EventType.
   *
   * @param monitor The Monitor context information and optional EventCallback.
   *
   * @return If the Monitor is not appropriate (mismatched type) fail.
   */
  virtual Status addMonitor(const MonitorRef monitor) {
    monitors_.push_back(monitor);
    return Status(0, "OK");
  }

  /// Number of Monitor%s watching this EventType.
  size_t numMonitors() { return monitors_.size(); }

  /**
   * @brief The number of events fired by this EventType.
   *
   * @return The number of events.
   */
  size_t numEvents() { return next_ec_id_; }

  /// Overriding the EventType constructor is not recommended.
  EventType() : next_ec_id_(0) {};

  /// Return a string identifier associated with this EventType.
  virtual EventTypeID type() const = 0;

  /// Return a string identifier for the given EventType symbol.
  template <typename T>
  static EventTypeID type() {
    const auto& event_type = new T();
    auto type_id = event_type->type();
    delete event_type;
    return type_id;
  }

 protected:
  /**
   * @brief The generic check loop to call MonitorContext callback methods.
   *
   * It is NOT recommended to override `fire`. The simple logic of enumerating
   * the Monitor%s and using `shouldFire` is more appropraite.
   *
   * @param ec The EventContext created and fired by the EventType.
   * @param time The most accurate time associated with the event.
   */
  void fire(const EventContextRef ec, EventTime time = 0);

 protected:
  /**
   * @brief The generic `fire` will call `shouldFire` for each Monitor.
   *
   * @param mc A MonitorContext with optional specifications for events details.
   * @param ec The event fired with event details.
   *
   * @return should the Monitor%'s EventCallback be called for this event.
   */
  virtual bool shouldFire(const MonitorContextRef mc, const EventContextRef ec);

 protected:
  /// The EventType will keep track of Monitor%s that contain callins.
  MonitorVector monitors_;

  /// An Event ID is assigned by the EventType within the EventContext.
  /// This is not used to store event date in the backing store.
  EventContextID next_ec_id_;

 private:
  /// A lock for incrementing the next EventContextID.
  boost::mutex ec_id_lock_;

 private:
  FRIEND_TEST(EventsTests, test_fire_event);
};

/**
 * @brief An interface binding Monitors, event response, and table generation.
 *
 * Use the EventModule interface when adding event monitors and defining callin
 * functions. The EventCallback is usually a member function for an EventModule.
 * The EventModule interface includes a very important `add` method
 * that abstracts the needed event to backing store interaction.
 *
 * Storing event data in the backing store must match a table spec for queries.
 * Small overheads exist that help query-time indexing and lookups.
 */
class EventModule {
 public:
  /// Called after EventType `setUp`. Add all Monitor%s here.
  /**
   * @brief Add Monitor%s to the EventType this module will act on.
   *
   * When the EventModule%'s `init` method is called you are assured the
   * EventType has `setUp` and is ready to monitor for events.
   */
  virtual void init() {}

  /**
   * @brief Suggested entrypoint for table generation.
   *
   * The EventModule is a convention that removes a lot of boilerplate event
   * monitoring and acting. The `genTable` static entrypoint is the suggested
   * method for table specs.
   *
   * @return The query-time table data, retrieved from a backing store.
   */
  static QueryData genTable();

 protected:
  /**
   * @brief Store parsed event data from an EventCallback in a backing store.
   *
   * Within a EventCallback the EventModule has an opprotunity to create
   * an osquery Row element, add the relevant table data for the EventModule
   * and store that element in the osquery backing store. At query-time
   * the added data will apply selection criteria and return these elements.
   * The backing store data retrieval is optimized by time-based indexes. It 
   * is important to added EventTime as it relates to "when the event occured".
   *
   * @param r An osquery Row element.
   * @param time The time the added event occured.
   *
   * @return Was the element added to the backing store.
   */
  virtual Status add(const osquery::Row& r, EventTime time) final;

  /**
   * @brief Return all events added by this EventModule within start, stop.
   *
   * This is used internally (for the most part) by EventModule::genTable.
   *
   * @param start Inclusive lower bound time limit.
   * @param stop Inclusive upper bound time limit.
   * @return Set of event rows matching time limits.
   */
  virtual QueryData get(EventTime start, EventTime stop);

  /*
   * @brief When `get`ting event results, return EventID%s from time indexes.
   *
   * Used by EventModule::get to retrieve EventID, EventTime indexes. This
   * applies the lookup-efficiency checks for time list appropriate bins.
   * If the time range in 24 hours and there is a 24-hour list bin it will
   * be queried using a single backing store `Get` followed by two `Get`s of
   * the most-specific boundary lists.
   *
   * @return List of EventID, EventTime%s
   */
  std::vector<EventRecord> getRecords(EventTime start, EventTime stop);

 private:
  /**
   * @brief Get a unique storage-related EventID.
   *
   * An EventID is an index/element-identifier for the backing store.
   * Each EventType maintains a fired EventContextID to identify the many
   * events that may or may not be fired to monitoring criteria for this
   * EventModule. This EventContextID is NOT the same as an EventID.
   * EventModule development should not require use of EventID%s, if this
   * indexing is required within-EventCallback consider an EventModule%-unique
   * indexing, counting mechanic.
   *
   * @return A unique ID for backing storage.
   */
  EventID getEventID();

  /*
   * @brief Add an EventID, EventTime pair to all matching list types.
   *
   * The list types are defined by time size. Based on the EventTime this pair
   * is added to the list bin for each list type. If there are two list types:
   * 60 seconds and 3600 seconds and `time` is 92, this pair will be added to
   * list type 1 bin 4 and list type 2 bin 1.
   *
   * @param eid A unique EventID.
   * @param time The time when this EventID%'s event occured.
   *
   * @return Were the indexes recorded.
   */
  Status recordEvent(EventID eid, EventTime time);

 protected:
  /**
   * @brief A single instance requirement for static callback facilities.
   *
   * The EventModule constructor is NOT responsible for adding Monitor%s.
   * Please use `init` for adding Monitor%s as all EventType instances will
   * have run `setUp` and initialized their run loops.
   */
  EventModule() {}

  /// Backing storage indexing namespace definition methods.
  EventTypeID dbNamespace() { return type() + "." + name(); }
  /// The string EventType identifying this EventModule.
  virtual EventTypeID type() const = 0;
  /// The string name identifying this EventModule.
  virtual EventTypeID name() const = 0;

 private:
  /// Lock used when incrementing the EventID database index.
  boost::mutex event_id_lock_;

  /// Lock used when recording an EventID and time into search bins.
  boost::mutex event_record_lock_;

 private:
  FRIEND_TEST(EventsDatabaseTests, test_event_module_id);
  FRIEND_TEST(EventsDatabaseTests, test_unique_event_module_id);
};

/**
 * @brief A factory for associating event generators to EventTypeID%s.
 *
 * This factory both registers new event types and the monitors that use them.
 * An EventType is also a factory, the single event factory arbitates Monitor
 * creatating and management for each associated EventType.
 *
 * Since event types may be plugins, they are created using the factory.
 * Since monitors may be configured/disabled they are also factory-managed.
 */
class EventFactory {
 public:
  /// Access to the EventFactory instance.
  static std::shared_ptr<EventFactory> getInstance();

  /**
   * @brief Add an EventType to the factory.
   *
   * The registration is mostly abstracted using osquery's registery.
   */
  template <typename T>
  static Status registerEventType() {
    auto event_type = std::make_shared<T>();
    return EventFactory::registerEventType(event_type);
  }

  /**
   * @brief Add an EventType to the factory.
   *
   * The registration is mostly abstracted using osquery's registery.
   *
   * @param event_type If for some reason the caller needs access to the
   * EventType instance they can register-by-instance.
   *
   * Access to the EventType instance is not discouraged, but using the
   * EventFactory `getEventType` accessor is encouraged.
   */
  static Status registerEventType(const EventTypeRef event_type);

  /**
   * @brief Add an EventModule to the factory.
   *
   * The registration is mostly abstracted using osquery's registery.
   */
  template <typename T>
  static Status registerEventModule() {
    auto event_module = T::getInstance();
    return EventFactory::registerEventModule(event_module);
  }

  /**
   * @brief Add an EventModule to the factory.
   *
   * The registration is mostly abstracted using osquery's registery.
   *
   * @param event_module If the caller must access the EventModule instance
   * control may be passed to the registry.
   *
   * Access to the EventModule instance outside of the within-instance
   * table generation method and set of EventCallback%s is discouraged.
   */
  static Status registerEventModule(const EventModuleRef event_module);

  /**
   * @brief Add a MonitorContext and EventCallback Monitor to an EventType.
   *
   * Create a Monitor from a given MonitorContext and EventCallback and
   * add that Monitor to the EventType assosicated identiter.
   *
   * @param type_id The string for an EventType receiving the Monitor.
   * @param mc A MonitorContext related to the EventType.
   * @param cb When the EventType fires an event the MonitorContext will
   * be evaluated, if the event matches optional specifics in the context this
   * callback function will be called. It should belong to an EventMonitor.
   *
   * @return Was the MonitorContext appropriate for the EventType.
   */
  static Status addMonitor(EventTypeID type_id,
                           const MonitorContextRef mc,
                           EventCallback cb = 0);

  /// Add a Monitor using a caller Monitor instance.
  static Status addMonitor(EventTypeID type_id, const MonitorRef monitor);

  /// Add a Monitor by templating the EventType, using a MonitorContext.
  template <typename T>
  static Status addMonitor(const MonitorContextRef mc, EventCallback cb = 0) {
    return addMonitor(EventType::type<T>(), mc, cb);
  }

  /// Add a Monitor by templating the EventType, using a Monitor instance.
  template <typename T>
  static Status addMonitor(const MonitorRef monitor) {
    return addMonitor(EventType::type<T>(), monitor);
  }

  /// Get the total number of Monitor%s across ALL EventType%s.
  static size_t numMonitors(EventTypeID type_id);

  /// Get the number of EventTypes.
  static size_t numEventTypes() {
    return EventFactory::getInstance()->event_types_.size();
  }

  /**
   * @brief Halt the EventType run loop and call its `tearDown`.
   *
   * Any EventModule%s with Monitor%s for this EventType will become useless.
   * osquery instanciators MUST deregister events.
   * EventType%s assume they can hook/trampoline, which requires cleanup.
   *
   * @param event_type The string label for the EventType.
   *
   * @return Did the EventType deregister cleanly.
   */
  static Status deregisterEventType(const EventTypeRef event_type);

  /// Deregister an EventType by EventTypeID.
  static Status deregisterEventType(EventTypeID type_id);

  /// Deregister all EventType%s.
  static Status deregisterEventTypes();

  /// Return an instance to a registered EventType.
  static EventTypeRef getEventType(EventTypeID);

 public:
  /// The dispatched event thread's entrypoint (if needed).
  static Status run(EventTypeID type_id);

  /// An initializer's entrypoint for spawning all event type run loops.
  static void delay();

  /**
   * @brief End all EventType run loops and call their `tearDown` methods.
   *
   * End is NOT the same as deregistration.
   *
   * @param should_end Reset the "is ending" state if False.
   */
  static void end(bool should_end = true);

 private:
  /// An EventFactory will exist for the lifetime of the application.
  EventFactory() { ending_ = false; }

 private:
  /// Set ending to True to cause event type run loops to finish.
  bool ending_;

  /// Set of registered EventType instances.
  EventTypeMap event_types_;

  /// Set of running EventType run loop threads.
  std::vector<std::shared_ptr<boost::thread>> threads_;

  /// Set of instanciated EventModule Monitor sets (with callbacks and state).
  std::vector<EventModuleRef> event_modules_;
};
}

/// Expose a Plugin-like Registry for EventType instances.
DECLARE_REGISTRY(EventTypes, std::string, EventTypeRef);
#define REGISTERED_EVENTTYPES REGISTRY(EventTypes)
#define REGISTER_EVENTTYPE(decorator) \
  REGISTER(EventTypes, #decorator, std::make_shared<decorator>());

/**
 * @brief Expose a Plugin-link Registry for EventModule instances.
 *
 * In most cases the EventModule class will organize itself to include
 * an generator entry point for query-time table generation too.
 */
DECLARE_REGISTRY(EventModules, std::string, EventModuleRef);
#define REGISTERED_EVENTMODULES REGISTRY(EventModules)
#define REGISTER_EVENTMODULE(decorator) \
  REGISTER(EventModules, #decorator, decorator::getInstance());

namespace osquery {
namespace registries {
/**
 * @brief A utility method for moving EventType%s and EventModule%s (plugins)
 * into the EventFactory.
 *
 * To handle run-time and compile-time EventType and EventModule additions
 * as plugins or extensions, the osquery Registry workflow is used. During
 * application launch (or within plugin load) the EventFactory faucet moves
 * managed instances of these types to the EventFactory. The EventType and
 * EventModule lifecycle/developer workflow is unknown to the Registry.
 */
void faucet(EventTypes ets, EventModules ems);
}
}
