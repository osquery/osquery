/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include <osquery/core.h>
#include <osquery/dispatcher.h>
#include <osquery/registry.h>
#include <osquery/status.h>
#include <osquery/tables.h>

namespace osquery {

struct Subscription;
template <class SC, class EC>
class EventPublisher;
template <class PUB>
class EventSubscriber;
class EventFactory;

using EventPublisherID = const std::string;
using EventSubscriberID = const std::string;
using EventID = const std::string;
using EventContextID = uint64_t;
using EventTime = uint64_t;
using EventRecord = std::pair<EventID, EventTime>;

/**
 * @brief An EventPublisher will define a SubscriptionContext for
 * EventSubscriber%s to use.
 *
 * Most EventPublisher%s will require specific information for interacting with
 * an OS to receive events. The SubscriptionContext contains information the
 * EventPublisher will use to register OS API callbacks, create
 * subscriptioning/listening handles, etc.
 *
 * Linux `inotify` should implement a SubscriptionContext that subscribes
 * filesystem events based on a filesystem path. `libpcap` will subscribe on
 * networking protocols at various stacks. Process creation may subscribe on
 * process name, parent pid, etc.
 */
struct SubscriptionContext : private boost::noncopyable {};

/**
 * @brief An EventSubscriber EventCallback method will receive an EventContext.
 *
 * The EventContext contains the event-related data supplied by an
 * EventPublisher when the event occurs. If a subscribing EventSubscriber
 * would be called for the event, the EventSubscriber%'s EventCallback is
 * passed an EventContext.
 */
struct EventContext : private boost::noncopyable {
  /// An unique counting ID specific to the EventPublisher%'s fired events.
  EventContextID id{0};

  /// The time the event occurred, as determined by the publisher.
  EventTime time{0};
};

using SubscriptionRef = std::shared_ptr<Subscription>;
using BaseEventPublisher = EventPublisher<SubscriptionContext, EventContext>;
using EventPublisherRef = std::shared_ptr<BaseEventPublisher>;
using SubscriptionContextRef = std::shared_ptr<SubscriptionContext>;
using EventContextRef = std::shared_ptr<EventContext>;
using BaseEventSubscriber = EventSubscriber<BaseEventPublisher>;
using EventSubscriberRef = std::shared_ptr<EventSubscriber<BaseEventPublisher>>;

/**
 * @brief EventSubscriber%s and Publishers may exist in various states.
 *
 * The class will move through states when osquery is initializing the
 * registry, starting event publisher loops, and requesting initialization of
 * each subscriber and the optional set of subscriptions it creates. If this
 * initialization fails the publishers or EventFactory may eject, warn, or
 * otherwise not use the subscriber's subscriptions.
 *
 * The supported states are:
 * - None: The default state, uninitialized.
 * - Setup: The Subscriber is attached and has run setup.
 * - Running: Subscriber is ready for events.
 * - Paused: Subscriber was initialized but is not currently accepting events.
 * - Failed: Subscriber failed to initialize or is otherwise offline.
 */
enum class EventState {
  EVENT_NONE = 0,
  EVENT_SETUP,
  EVENT_RUNNING,
  EVENT_PAUSED,
  EVENT_FAILED,
};

/// Use a single placeholder for the EventContextRef passed to EventCallback.
using EventCallback = std::function<Status(const EventContextRef&,
                                           const SubscriptionContextRef&)>;

/// An EventPublisher must track every subscription added.
using SubscriptionVector = std::vector<SubscriptionRef>;

/// The set of search-time binned lookup tables.
extern const std::vector<size_t> kEventTimeLists;

/**
 * @brief DECLARE_PUBLISHER supplies needed boilerplate code that applies a
 * string-type EventPublisherID to identify the publisher declaration.
 */
#define DECLARE_PUBLISHER(TYPE)                                                \
 public:                                                                       \
  EventPublisherID type() const override final {                               \
    return TYPE;                                                               \
  }

/**
 * @brief A Subscription is used to configure an EventPublisher and bind a
 * callback to a SubscriptionContext.
 *
 * A Subscription is the input to an EventPublisher when the EventPublisher
 * decides on the scope and details of the events it watches/generates.
 * An example includes a filesystem change event. A subscription would include
 * a path with optional recursion and attribute selectors as well as a callback
 * function to fire when an event for that path and selector occurs.
 *
 * A Subscription also functions to greatly scope an EventPublisher%'s work.
 * Using the same filesystem example and the Linux inotify subsystem a
 * Subscription limits the number of inode watches to only those requested by
 * appropriate EventSubscriber%s.
 * Note: EventSubscriber%s and Subscriptions can be configured by the osquery
 * user.
 *
 * Subscriptions are usually created with EventFactory members:
 *
 * @code{.cpp}
 *   EventFactory::addSubscription("MyEventPublisher", my_subscription_context);
 * @endcode
 */
struct Subscription : private boost::noncopyable {
 public:
  // EventSubscriber name.
  std::string subscriber_name;

  /// An EventPublisher%-specific SubscriptionContext.
  SubscriptionContextRef context;

  /// An EventSubscription member EventCallback method.
  EventCallback callback;

  explicit Subscription(EventSubscriberID& name) : subscriber_name(name){};

  static SubscriptionRef create(EventSubscriberID& name) {
    return std::make_shared<Subscription>(name);
  }

  static SubscriptionRef create(EventSubscriberID& name,
                                const SubscriptionContextRef& mc,
                                EventCallback ec = nullptr) {
    auto subscription = std::make_shared<Subscription>(name);
    subscription->context = mc;
    subscription->callback = ec;
    return subscription;
  }

 public:
  Subscription() = delete;
};

class Eventer {
 public:
  /**
   * @brief Request the subscriber's initialization state.
   *
   * When event subscribers are created (initialized) they are expected to emit
   * a set of subscriptions to their publisher "type". If the subscriber fails
   * to initialize then the publisher may remove any intermediate subscriptions.
   */
  EventState state() const {
    return state_;
  }

 protected:
  /// Set the subscriber state.
  void state(EventState state) {
    state_ = state;
  }

 private:
  /// The event subscriber's run state.
  EventState state_{EventState::EVENT_NONE};

  friend class EventFactory;
};

class EventPublisherPlugin : public Plugin,
                             public InterruptableRunnable,
                             public Eventer {
 public:
  /**
   * @brief A new Subscription was added, potentially change state based on all
   * subscriptions for this EventPublisher.
   *
   * `configure` allows the EventPublisher to optimize on the state of all
   * subscriptions. An example is Linux `inotify` where multiple
   * EventSubscription%s will subscription identical paths, e.g., /etc for
   * config changes. Since Linux `inotify` has a subscription limit, `configure`
   * can dedup paths.
   */
  virtual void configure() override{};

  /**
   * @brief Perform handle opening, OS API callback registration.
   *
   * `setUp` is the event framework's EventPublisher constructor equivalent.
   * This is called in the main thread before the publisher's run loop has
   * started, immediately following registration.
   */
  virtual Status setUp() override {
    return Status(0, "Not used");
  }

  /**
   * @brief Perform handle closing, resource cleanup.
   *
   * osquery is about to end, the EventPublisher should close handle descriptors
   * unblock resources, and prepare to exit. This will be called from the main
   * thread after the run loop thread has exited.
   */
  virtual void tearDown() override {}

  /**
   * @brief Implement a "step" of an optional run loop.
   *
   * @return A SUCCESS status will immediately call `run` again. A FAILED status
   * will exit the run loop and the thread.
   */
  virtual Status run() {
    return Status(1, "No run loop required");
  }

  /**
   * @brief Allow the EventFactory to interrupt the run loop.
   *
   * Assume the main thread may ask the run loop to stop at anytime.
   * Before end is called the publisher's `isEnding` is set and the EventFactory
   * run loop manager will exit the stepping loop and fall through to a call
   * to tearDown followed by a removal of the publisher.
   */
  virtual void stop() override {}

  /// This is a plugin type and must implement a call method.
  Status call(const PluginRequest&, PluginResponse&) override {
    return Status(0);
  }

  /**
   * @brief A new EventSubscriber is subscribing events of this publisher type.
   *
   * @param subscription The Subscription context information and optional
   * EventCallback.
   *
   * @return If the Subscription is not appropriate (mismatched type) fail.
   */
  virtual Status addSubscription(const SubscriptionRef& subscription);

  /// Remove all subscriptions from a named subscriber.
  virtual void removeSubscriptions(const std::string& subscriber);

 public:
  /// Overriding the EventPublisher constructor is not recommended.
  EventPublisherPlugin() {}
  virtual ~EventPublisherPlugin() {}

  /// Return a string identifier associated with this EventPublisher.
  virtual EventPublisherID type() const {
    return "publisher";
  }

 public:
  /// Number of Subscription%s watching this EventPublisher.
  size_t numSubscriptions() const {
    return subscriptions_.size();
  }

  /**
   * @brief The number of events fired by this EventPublisher.
   *
   * @return The number of events.
   */
  EventContextID numEvents() const {
    return next_ec_id_;
  }

  /// Check if the EventFactory is ending all publisher threads.
  bool isEnding() const {
    return ending_;
  }

  /// Set the ending status for this publisher.
  void isEnding(bool ending) {
    ending_ = ending;
  }

  /// Check if the publisher's run loop has started.
  bool hasStarted() const {
    return started_;
  }

  /// Set the run or started status for this publisher.
  void hasStarted(bool started) {
    started_ = started;
  }

  /// Get the number of publisher restarts.
  size_t restartCount() const {
    return restart_count_;
  }

 public:
  explicit EventPublisherPlugin(EventPublisherPlugin const&) = delete;
  EventPublisherPlugin& operator=(EventPublisherPlugin const&) = delete;

 protected:
  /**
   * @brief The generic check loop to call SubscriptionContext callback methods.
   *
   * It is NOT recommended to override `fire`. The simple logic of enumerating
   * the Subscription%s and using `shouldFire` is more appropriate.
   *
   * @param ec The EventContext created and fired by the EventPublisher.
   * @param time The most accurate time associated with the event.
   */
  virtual void fire(const EventContextRef& ec, EventTime time = 0) final;

  /// The internal fire method used by the typed EventPublisher.
  virtual void fireCallback(const SubscriptionRef& sub,
                            const EventContextRef& ec) const = 0;

  /// The EventPublisher will keep track of Subscription%s that contain callins.
  SubscriptionVector subscriptions_;

  /// An Event ID is assigned by the EventPublisher within the EventContext.
  /// This is not used to store event date in the backing store.
  std::atomic<EventContextID> next_ec_id_{0};

 private:
  /// Set ending to True to cause event type run loops to finish.
  std::atomic<bool> ending_{false};

  /// Set to indicate whether the event run loop ever started.
  std::atomic<bool> started_{false};

  /// A lock for incrementing the next EventContextID.
  Mutex ec_id_lock_;

  /// A lock for subscription manipulation.
  Mutex subscription_lock_;

  /// A helper count of event publisher runloop iterations.
  std::atomic<size_t> restart_count_{0};

 private:
  /// Enable event factory "callins" through static publisher callbacks.
  friend class EventFactory;

 private:
  FRIEND_TEST(EventsTests, test_event_publisher);
  FRIEND_TEST(EventsTests, test_fire_event);
};

class EventSubscriberPlugin : public Plugin, public Eventer {
 public:
  /**
   * @brief Add Subscription%s to the EventPublisher this module will act on.
   *
   * When the EventSubscriber%'s `init` method is called you are assured the
   * EventPublisher has `setUp` and is ready to subscription for events.
   */
  virtual Status init() {
    return Status(0);
  }

  /// This is a plugin type and must implement a call method.
  Status call(const PluginRequest&, PluginResponse&) override {
    return Status(0);
  }

 protected:
  /**
   * @brief Store parsed event data from an EventCallback in a backing store.
   *
   * Within a EventCallback the EventSubscriber has an opportunity to create
   * an osquery Row element, add the relevant table data for the EventSubscriber
   * and store that element in the osquery backing store. At query-time
   * the added data will apply selection criteria and return these elements.
   * The backing store data retrieval is optimized by time-based indexes. It
   * is important to added EventTime as it relates to "when the event occurred".
   *
   * @param r An osquery Row element.
   *
   * @return Was the element added to the backing store.
   */
  Status add(Row& r) {
    return add(r, 0);
  }

  /**
   * @brief Return all events added by this EventSubscriber within start, stop.
   *
   * This is used internally (for the most part) by EventSubscriber::genTable.
   *
   * @param start Inclusive lower bound time limit.
   * @param stop Inclusive upper bound time limit.
   * @return Set of event rows matching time limits.
   */
  virtual QueryData get(EventTime start, EventTime stop) final;

 private:
  /// Overload add for tests and allow them to override the event time.
  virtual Status add(Row& r, EventTime event_time) final;

 private:
  /*
   * @brief When `get`ing event results, return EventID%s from time indexes.
   *
   * Used by EventSubscriber::get to retrieve EventID, EventTime indexes. This
   * applies the lookup-efficiency checks for time list appropriate bins.
   * If the time range in 24 hours and there is a 24-hour list bin it will
   * be queried using a single backing store `Get` followed by two `Get`s of
   * the most-specific boundary lists.
   *
   * @return List of EventID, EventTime%s
   */
  std::vector<EventRecord> getRecords(const std::vector<std::string>& indexes);

  /**
   * @brief Get a unique storage-related EventID.
   *
   * An EventID is an index/element-identifier for the backing store.
   * Each EventPublisher maintains a fired EventContextID to identify the many
   * events that may or may not be fired based on subscription criteria for this
   * EventSubscriber. This EventContextID is NOT the same as an EventID.
   * EventSubscriber development should not require use of EventID%s. If this
   * indexing is required within-EventCallback consider an
   * EventSubscriber%-unique indexing, counting mechanic.
   *
   * @return A unique ID for backing storage.
   */
  EventID getEventID();

  /**
   * @brief Plan the best set of indexes for event record access.
   *
   * @param start an inclusive time to begin searching.
   * @param stop an inclusive time to end searching.
   *
   * @return List of 'index.step' index strings.
   */
  std::vector<std::string> getIndexes(EventTime start, EventTime stop);

  /**
   * @brief Expire indexes and eventually records.
   *
   * @param list_type the string representation of list binning type.
   * @param indexes complete set of 'index.step' indexes for the list_type.
   * @param expirations of the indexes, the set to expire.
   */
  void expireIndexes(const std::string& list_type,
                     const std::vector<std::string>& indexes,
                     const std::vector<std::string>& expirations);

  /// Expire all datums within a bin.
  void expireRecords(const std::string& list_type,
                     const std::string& index,
                     bool all);

  /**
   * @brief Inspect the number of events, expire those overflowing events_max.
   *
   * When the event manager starts, or after a checkpoint number of events,
   * the EventFactory will call expireCheck for each subscriber.
   *
   * The subscriber must count the number of buffered records and check if
   * that count exceeds the configured `events_max` limit. If an overflow
   * occurs the subscriber will expire N-events_max from the end of the queue.
   *
   * @param cleanup Perform an intense scan of zombie event IDs.
   */
  void expireCheck(bool cleanup = false);

  /**
   * @brief Add an EventID, EventTime pair to all matching list types.
   *
   * The list types are defined by time size. Based on the EventTime this pair
   * is added to the list bin for each list type. If there are two list types:
   * 60 seconds and 3600 seconds and `time` is 92, this pair will be added to
   * list type 1 bin 4 and list type 2 bin 1.
   *
   * @param eid A unique EventID.
   * @param time The time when this EventID%'s event occurred.
   *
   * @return Were the indexes recorded.
   */
  Status recordEvent(EventID& eid, EventTime time);

  /**
   * @brief Get the expiration timeout for this event type
   *
   * The default implementation retrieves this value from FLAGS_events_expiry.
   * This method can be overridden to allow custom event expiration timeouts in
   * subclasses of EventSubscriberPlugin.
   *
   * @return The events expiration timeout for this event type
   */
  virtual size_t getEventsExpiry();

  /**
   * @brief Get the max number of events for this event type
   *
   * The default implementation retrieves this value from FLAGS_events_max.
   * This method can be overridden to allow custom max event numbers in
   * subclasses of EventSubscriberPlugin.
   *
   * @return The max number of events for this event type
   */
  virtual size_t getEventsMax();

 public:
  /**
   * @brief A single instance requirement for static callback facilities.
   *
   * The EventSubscriber constructor is NOT responsible for adding
   * Subscription%s. Please use `init` for adding Subscription%s as all
   * EventPublisher instances will have run `setUp` and initialized their run
   * loops.
   */
  EventSubscriberPlugin()
      : expire_events_(true), expire_time_(0), optimize_time_(0) {}
  virtual ~EventSubscriberPlugin() {}

  /**
   * @brief Suggested entrypoint for table generation.
   *
   * The EventSubscriber is a convention that removes a lot of boilerplate event
   * 'subscribing' and acting. The `genTable` static entrypoint is the
   * suggested method for table specs.
   *
   * @return The query-time table data, retrieved from a backing store.
   */
  virtual QueryData genTable(QueryContext& context) USED_SYMBOL;

  /// Number of Subscription%s this EventSubscriber has used.
  size_t numSubscriptions() const {
    return subscription_count_;
  }

  /// The number of events this EventSubscriber has received.
  EventContextID numEvents() const {
    return event_count_;
  }

 private:
  explicit EventSubscriberPlugin(EventSubscriberPlugin const&) = delete;
  EventSubscriberPlugin& operator=(EventSubscriberPlugin const&) = delete;

 protected:
  /**
   * @brief Backing storage indexing namespace.
   *
   * The backing storage will accumulate events for this subscriber. A namespace
   * is provided to prevent event indexing collisions between subscribers and
   * publishers. The namespace is a combination of the publisher and subscriber
   * registry plugin names.
   */
  /// See getType for lookup rational.
  virtual EventPublisherID dbNamespace() const {
    return getType() + '.' + getName();
  }

  /// Disable event expiration for this subscriber.
  void doNotExpire() {
    expire_events_ = false;
  }

  /// Trampoline into the EventFactory and lookup the name of the publisher.
  virtual EventPublisherID& getType() const = 0;

  /// Get a handle to the EventPublisher.
  EventPublisherRef getPublisher() const;

  /// Remove all subscriptions from this subscriber.
  void removeSubscriptions();

 protected:
  /// A helper value counting the number of fired events tracked by publishers.
  EventContextID event_count_{0};

  /// A helper value counting the number of subscriptions created.
  size_t subscription_count_{0};

 private:
  Status setUp() override {
    return Status(0, "Setup never used");
  }

 private:
  /// Do not respond to periodic/scheduled/triggered event expiration requests.
  bool expire_events_{false};

  /// Events before the expire_time_ are invalid and will be purged.
  EventTime expire_time_{0};

  /// Cached value of last generated EventID.
  size_t last_eid_{0};

  /**
   * @brief Optimize subscriber selects by tracking the last select time.
   *
   * Event subscribers may optimize selects when used in a daemon schedule by
   * requiring an event 'time' constraint and otherwise applying a minimum time
   * as the last time the scheduled query ran.
   */
  EventTime optimize_time_{0};

  /**
   * @brief Last event ID returned while using events-optimization.
   *
   * A time with second precision is not sufficient, but it works for index
   * retrieval. While sorting using the time optimization, discard events
   * before or equal to the optimization ID.
   */
  size_t optimize_eid_{0};

  /// Lock used when incrementing the EventID database index.
  Mutex event_id_lock_;

  /// Lock used when recording an EventID and time into search bins.
  Mutex event_record_lock_;

 private:
  friend class EventFactory;
  friend class EventPublisherPlugin;

 private:
  FRIEND_TEST(EventsDatabaseTests, test_event_module_id);
  FRIEND_TEST(EventsDatabaseTests, test_record_indexing);
  FRIEND_TEST(EventsDatabaseTests, test_record_range);
  FRIEND_TEST(EventsDatabaseTests, test_record_expiration);
  FRIEND_TEST(EventsDatabaseTests, test_gentable);
  FRIEND_TEST(EventsDatabaseTests, test_expire_check);
  FRIEND_TEST(EventsDatabaseTests, test_optimize);
  friend class DBFakeEventSubscriber;
  friend class BenchmarkEventSubscriber;
};

/**
 * @brief A factory for associating event generators to EventPublisherID%s.
 *
 * This factory both registers new event types and the subscriptions that use
 * them. An EventPublisher is also a factory, the single event factory
 * arbitrates Subscription creation and management for each associated
 * EventPublisher.
 *
 * Since event types may be plugins, they are created using the factory.
 * Since subscriptions may be configured/disabled they are also factory-managed.
 */
class EventFactory : private boost::noncopyable {
 public:
  /// Access to the EventFactory instance.
  static EventFactory& getInstance();

  /**
   * @brief Add an EventPublisher to the factory.
   *
   * The registration is mostly abstracted using osquery's registry.
   *
   * @param pub If for some reason the caller needs access to the
   * EventPublisher instance they can register-by-instance.
   *
   * Access to the EventPublisher instance is not discouraged, but using the
   * EventFactory `getEventPublisher` accessor is encouraged.
   */
  static Status registerEventPublisher(const PluginRef& pub);

  /**
   * @brief Add an EventSubscriber to the factory.
   *
   * The registration is mostly abstracted using osquery's registry.
   */
  template <class T>
  static Status registerEventSubscriber() {
    auto sub = std::make_shared<T>();
    return registerEventSubscriber(sub);
  };

  /**
   * @brief Add an EventSubscriber to the factory.
   *
   * The registration is mostly abstracted using osquery's registry.
   *
   * @param sub If the caller must access the EventSubscriber instance
   * control may be passed to the registry.
   *
   * Access to the EventSubscriber instance outside of the within-instance
   * table generation method and set of EventCallback%s is discouraged.
   */
  static Status registerEventSubscriber(const PluginRef& sub);

  /**
   * @brief Add a SubscriptionContext and EventCallback Subscription to an
   * EventPublisher.
   *
   * Create a Subscription from a given SubscriptionContext and EventCallback
   * and add that Subscription to the EventPublisher associated identifier.
   *
   * @param type_id ID string for an EventPublisher receiving the Subscription.
   * @param name_id ID string for the EventSubscriber.
   * @param sc A SubscriptionContext related to the EventPublisher.
   * @param cb When the EventPublisher fires an event the SubscriptionContext
   * will be evaluated, if the event matches optional specifics in the context
   * this callback function will be called. It should belong to an
   * EventSubscription.
   *
   * @return Was the SubscriptionContext appropriate for the EventPublisher.
   */
  static Status addSubscription(EventPublisherID& type_id,
                                EventSubscriberID& name_id,
                                const SubscriptionContextRef& sc,
                                EventCallback cb = nullptr);

  /// Add a Subscription using a caller Subscription instance.
  static Status addSubscription(EventPublisherID& type_id,
                                const SubscriptionRef& subscription);

  /// Get the total number of Subscription%s across ALL EventPublisher%s.
  static size_t numSubscriptions(EventPublisherID& type_id);

  /// Get the number of EventPublishers.
  static size_t numEventPublishers() {
    return EventFactory::getInstance().event_pubs_.size();
  }

  /**
   * @brief Halt the EventPublisher run loop.
   *
   * Any EventSubscriber%s with Subscription%s for this EventPublisher will
   * become useless. osquery callers MUST deregister events.
   * EventPublisher%s assume they can hook/trampoline, which requires cleanup.
   * This will tear down and remove the publisher if the run loop did not start.
   * Otherwise it will call end on the publisher and assume the run loop will
   * tear down and remove.
   *
   * @param pub The string label for the EventPublisher.
   *
   * @return Did the EventPublisher deregister cleanly.
   */
  static Status deregisterEventPublisher(const EventPublisherRef& pub);

  /// Deregister an EventPublisher by EventPublisherID.
  static Status deregisterEventPublisher(EventPublisherID& type_id);

  /// Return an instance to a registered EventPublisher.
  static EventPublisherRef getEventPublisher(EventPublisherID& pub);

  /// Return an instance to a registered EventSubscriber.
  static EventSubscriberRef getEventSubscriber(EventSubscriberID& sub);

  /// Check if an event subscriber exists.
  static bool exists(EventSubscriberID& sub);

  /// Return a list of publisher types, these are their registry names.
  static std::vector<std::string> publisherTypes();

  /// Return a list of subscriber registry names,
  static std::vector<std::string> subscriberNames();

  /// Set log forwarding by adding a logger receiver.
  static void addForwarder(const std::string& logger);

  /// Optionally forward events to loggers.
  static void forwardEvent(const std::string& event);

 public:
  /// The dispatched event thread's entry-point (if needed).
  static Status run(EventPublisherID& type_id);

  /// An initializer's entry-point for spawning all event type run loops.
  static void delay();

  /// If a static EventPublisher callback wants to fire
  template <typename PUB>
  static void fire(const EventContextRef& ec) {
    auto event_pub = getEventPublisher(getType<PUB>());
    event_pub->fire(ec);
  }

  /**
   * @brief Return the publisher registry name given a type.
   *
   * Subscriber initialization and runtime static callbacks can lookup the
   * publisher type name, which is the registry plugin name. This allows static
   * callbacks to fire into subscribers.
   */
  template <class PUB>
  static EventPublisherID getType() {
    auto pub = std::make_shared<PUB>();
    return pub->type();
  }

  /**
   * @brief End all EventPublisher run loops and deregister.
   *
   * End is NOT the same as deregistration. End will call deregister on all
   * publishers then either join or detach their run loop threads.
   * See EventFactory::deregisterEventPublisher for actions taken during
   * deregistration.
   *
   * @param join if true, threads will be joined
   */
  static void end(bool join = false);

 public:
  EventFactory(EventFactory const&) = delete;
  EventFactory& operator=(EventFactory const&) = delete;

 private:
  /// An EventFactory will exist for the lifetime of the application.
  EventFactory() {}
  ~EventFactory() {}

 private:
  /// Set of registered EventPublisher instances.
  std::map<EventPublisherID, EventPublisherRef> event_pubs_;

  /// Set of instantiated EventSubscriber subscriptions.
  std::map<EventSubscriberID, EventSubscriberRef> event_subs_;

  /// Set of running EventPublisher run loop threads.
  std::vector<std::shared_ptr<std::thread>> threads_;

  /// Set of logger plugins to forward events.
  std::vector<std::string> loggers_;

  /// Factory publisher state manipulation.
  Mutex factory_lock_;
};

/**
 * @brief Generate OS events of a type (FS, Network, Syscall, ioctl).
 *
 * A 'class' of OS events is abstracted into an EventPublisher responsible for
 * remaining as agile as possible given a known-set of subscriptions.
 *
 * The life cycle of an EventPublisher may include, `setUp`, `configure`, `run`,
 * `tearDown`, and `fire`. `setUp` and `tearDown` happen when osquery starts and
 * stops either as a daemon or interactive shell. `configure` is a pseudo-start
 * called every time a Subscription is added. EventPublisher%s can adjust their
 * scope/agility specific to each added subscription by overriding
 *`addSubscription`, and/or globally in `configure`.
 *
 * Not all EventPublisher%s leverage pure async OS APIs, and most will require a
 * run loop either polling with a timeout on a descriptor or for a change. When
 * osquery initializes the EventFactory will optionally create a thread for each
 * EventPublisher using `run` as the thread's entrypoint. `run` is called in a
 * within-thread loop where returning a FAILED status ends the run loop and
 * shuts down the thread.
 *
 * To opt-out of polling in a thread, consider the following run implementation:
 *
 * @code{.cpp}
 *   Status run() { return Status(1, "Not Implemented"); }
 * @endcode
 *
 * The final life cycle component, `fire` will iterate over the EventPublisher
 * Subscription%s and call `shouldFire` for each, using the EventContext fired.
 * The `shouldFire` method should check the subscription-specific selectors and
 * only call the Subscription%'s callback function if the EventContext
 * (thus event) matches.
 */
template <typename SC, typename EC>
class EventPublisher : public EventPublisherPlugin {
 public:
  /// A nested helper typename for the templated SubscriptionContextRef.
  using SCRef = typename std::shared_ptr<SC>;
  /// A nested helper typename for the templated EventContextRef.
  using ECRef = typename std::shared_ptr<EC>;

 public:
  EventPublisher(){};
  virtual ~EventPublisher() {}

  /// Up-cast a base EventContext reference to the templated ECRef.
  static ECRef getEventContext(const EventContextRef& ec) {
    return std::static_pointer_cast<EC>(ec);
  };

  /// Up-cast a base SubscriptionContext reference to the templated SCRef.
  static SCRef getSubscriptionContext(const SubscriptionContextRef& sc) {
    return std::static_pointer_cast<SC>(sc);
  }

  /// Create a EventContext based on the templated type.
  static ECRef createEventContext() {
    return std::make_shared<EC>();
  }

  /// Create a SubscriptionContext based on the templated type.
  static SCRef createSubscriptionContext() {
    return std::make_shared<SC>();
  }

 protected:
  /**
   * @brief The internal `fire` phase of publishing.
   *
   * This is a template-generated method that up-casts the generic fired
   * event/subscription contexts, and calls the callback if the event should
   * fire given a subscription.
   *
   * @param sub The SubscriptionContext and optional EventCallback.
   * @param ec The event that was fired.
   */
  void fireCallback(const SubscriptionRef& sub,
                    const EventContextRef& ec) const override {
    auto pub_sc = getSubscriptionContext(sub->context);
    auto pub_ec = getEventContext(ec);
    if (shouldFire(pub_sc, pub_ec) && sub->callback != nullptr) {
      sub->callback(pub_ec, pub_sc);
    }
  }

 protected:
  /**
   * @brief The generic `fire` will call `shouldFire` for each Subscription.
   *
   * @param sc A SubscriptionContext with optional specifications for events
   * details.
   * @param ec The event fired with event details.
   *
   * @return should the Subscription%'s EventCallback be called for this event.
   */
  virtual bool shouldFire(const SCRef& sc, const ECRef& ec) const {
    return true;
  }

 private:
  FRIEND_TEST(EventsTests, test_event_subscriber_subscribe);
  FRIEND_TEST(EventsTests, test_event_subscriber_context);
  FRIEND_TEST(EventsTests, test_fire_event);
};

/**
 * @brief An interface binding Subscriptions, event response, and table
 *generation.
 *
 * Use the EventSubscriber interface when adding event subscriptions and
 * defining callin functions. The EventCallback is usually a member function
 * for an EventSubscriber. The EventSubscriber interface includes a very
 * important `add` method that abstracts the needed event to backing store
 * interaction.
 *
 * Storing event data in the backing store must match a table spec for queries.
 * Small overheads exist that help query-time indexing and lookups.
 */
template <class PUB>
class EventSubscriber : public EventSubscriberPlugin {
 protected:
  using SCRef = typename PUB::SCRef;
  using ECRef = typename PUB::ECRef;

 public:
  /**
   * @brief The registry plugin name for the subscriber's publisher.
   *
   * During event factory initialization the subscribers 'peek' at the registry
   * plugin name assigned to publishers. The corresponding publisher name is
   * interpreted as the subscriber's event 'type'.
   */
  virtual EventPublisherID& getType() const override {
    static EventPublisherID type = EventFactory::getType<PUB>();
    return type;
  };

 protected:
  /// Helper function to call the publisher's templated subscription generator.
  SCRef createSubscriptionContext() const {
    return PUB::createSubscriptionContext();
  }

  /**
   * @brief Bind a registered EventSubscriber member function to a Subscription.
   *
   * @param entry A templated EventSubscriber member function.
   * @param sc The subscription context.
   */
  template <class T, typename E>
  void subscribe(Status (T::*entry)(const std::shared_ptr<E>&, const SCRef&),
                 const SCRef& sc) {
    using std::placeholders::_1;
    using std::placeholders::_2;
    using CallbackFunc =
        Status (T::*)(const EventContextRef&, const SubscriptionContextRef&);

    // Down-cast the pointer to the member function.
    auto base_entry = reinterpret_cast<CallbackFunc>(entry);
    // Up-cast the EventSubscriber to the caller.
    auto sub = dynamic_cast<T*>(this);
    if (base_entry != nullptr && sub != nullptr) {
      // Create a callable through the member function using the instance of the
      // EventSubscriber and a single parameter placeholder (the EventContext).
      auto cb = std::bind(base_entry, sub, _1, _2);
      // Add a subscription using the callable and SubscriptionContext.
      EventFactory::addSubscription(sub->getType(), sub->getName(), sc, cb);
      subscription_count_++;
    }
  }

 public:
  explicit EventSubscriber(bool enabled = true)
      : EventSubscriberPlugin(), disabled(!enabled) {}
  virtual ~EventSubscriber() {}

 protected:
  /**
   * @brief Allow subscriber implementations to default disable themselves.
   *
   * A subscriber may induce latency on a system within the callback routines.
   * Before the initialization and set up is performed the EventFactory can
   * choose to exclude a subscriber if it is not explicitly enabled within
   * the config.
   *
   * EventSubscriber%s that should be default-disabled should set this flag
   * in their constructor or worst case before EventSubsciber::init.
   */
  bool disabled{false};

 private:
  friend class EventFactory;

 private:
  FRIEND_TEST(EventsTests, test_event_sub);
  FRIEND_TEST(EventsTests, test_event_sub_subscribe);
  FRIEND_TEST(EventsTests, test_event_sub_context);
  FRIEND_TEST(EventsTests, test_event_toggle_subscribers);
};

/// Iterate the event publisher registry and create run loops for each using
/// the event factory.
void attachEvents();
}
