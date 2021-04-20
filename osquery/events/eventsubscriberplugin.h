/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <gtest/gtest_prod.h>

#include <osquery/core/plugins/plugin.h>
#include <osquery/core/tables.h>
#include <osquery/database/database.h>
#include <osquery/events/eventer.h>
#include <osquery/events/types.h>
#include <osquery/utils/mutex.h>

namespace osquery {

class EventSubscriberPlugin : public Plugin, public Eventer {
 public:
  /**
   * @brief Add Subscription%s to the EventPublisher this module will act on.
   *
   * When the EventSubscriber%'s `init` method is called you are assured the
   * EventPublisher has `setUp` and is ready to subscription for events.
   */
  virtual Status init();

  /// This is a plugin type and must implement a call method.
  virtual Status call(const PluginRequest&, PluginResponse&) override;

 protected:
  /**
   * @brief Store parsed event data from an EventCallback in a backing store.
   *
   * This method stores a single event
   *
   * @param r The row to add
   *
   * @return Was the element added to the backing store.
   */

  // clang-format off
  [[deprecated("Group events together and use addBatch() instead.")]]
  // clang-format on
  Status
  add(const Row& r);

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
   * @param row_list A (writable) vector of osquery Row elements.
   *
   * @return Was the element added to the backing store.
   */
  Status addBatch(std::vector<Row>& row_list);

 private:
  /// Overload add for tests and allow them to override the event time.
  virtual Status addBatch(std::vector<Row>& row_list,
                          EventTime custom_event_time) final;

  /// Scans the database to enumerate all the data keys and build a new index
  Status generateEventDataIndex();

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
   * @brief Get the max number of event batches for this event type
   *
   * The default implementation retrieves this value from FLAGS_events_max.
   * This method can be overridden to allow custom max event numbers in
   * subclasses of EventSubscriberPlugin.
   *
   * @return The max number of events for this event type
   */
  virtual size_t getEventBatchesMax();

  /// Determine if the subscriber should attempt optmization.
  virtual bool shouldOptimize() const;

  /**
   * @brief Return all events added by this EventSubscriber within start, stop.
   *
   * This is used internally (for the most part) by EventSubscriber::genTable.
   *
   * @param callback A callback encapsulating Row yield method.
   * @param can_optimize If true then optimization can be considered.
   * @param start_time Inclusive lower bound time limit.
   * @param end_time Inclusive upper bound time limit.
   * @return Set of event rows matching time limits.
   */
  void generateRows(std::function<void(Row)> callback,
                    bool can_optimize,
                    EventTime start_time,
                    EventTime stop_stop);

  /// Track a query execution.
  virtual void setExecutedQuery(const std::string& query_name,
                                uint64_t query_time);

  /// Set the number of queries in the schedule using this subscriber.
  void resetQueryCount(size_t count);

  /// Return the smallest expiry window based on the query schedule.
  size_t getMinExpiry();

  /// Set a minimum expiration windows based on the query schedule.
  void setMinExpiry(size_t expiry);

  /// Return either the current time or the oldest optimized time.
  uint64_t getExpireTime();

 public:
  /**
   * @brief A single instance requirement for static callback facilities.
   *
   * The EventSubscriber constructor is NOT responsible for adding
   * Subscription%s. Please use `init` for adding Subscription%s as all
   * EventPublisher instances will have run `setUp` and initialized their run
   * loops.
   */
  explicit EventSubscriberPlugin(bool enabled);

  virtual ~EventSubscriberPlugin() override = default;

  /**
   * @brief Suggested entrypoint for table generation.
   *
   * The EventSubscriber is a convention that removes a lot of boilerplate event
   * 'subscribing' and acting. The `genTable` static entrypoint is the
   * suggested method for table specs.
   *
   * @param yield The Row yield method.
   * @param ctx The query context (used for time windows).
   * @return The query-time table data, retrieved from a backing store.
   */
  virtual void genTable(RowYield& yield, QueryContext& ctx) USED_SYMBOL;

  /// Number of Subscription%s this EventSubscriber has used.
  size_t numSubscriptions() const;

  /// The number of events this EventSubscriber has received.
  EventContextID numEvents() const;

  /// Compare the number of queries run against the queries configured.
  virtual bool executedAllQueries() const;

  struct Context final {
    std::string database_namespace;
    EventIndex event_index;
    Mutex event_index_mutex;

    std::size_t last_query_time{0U};
    std::atomic<EventID> last_event_id{0U};
  };

  static std::string toIndex(std::uint64_t i);

  static void setOptimizeData(IDatabaseInterface& db_interface,
                              EventTime time,
                              EventID eid);

  static EventTime timeFromRecord(const std::string& record);

  static void getOptimizeData(IDatabaseInterface& db_interface,
                              EventTime& o_time,
                              EventID& o_eid,
                              std::string& query_name);

  static EventID generateEventIdentifier(Context& context);

  static void setDatabaseNamespace(Context& context,
                                   const std::string& type,
                                   const std::string& name);

  static Status generateEventDataIndex(Context& context,
                                       IDatabaseInterface& db_interface);

  static std::string databaseKeyForEventId(Context& context, EventID event_id);

  static void removeOverflowingEventBatches(Context& context,
                                            IDatabaseInterface& db_interface,
                                            std::size_t max_event_batches);

  static void expireEventBatches(Context& context,
                                 IDatabaseInterface& db_interface,
                                 std::size_t events_expiry,
                                 std::size_t current_time);

  /**
   * @brief Return all events added by this EventSubscriber within start, stop.
   *
   * This is used internally (for the most part) by EventSubscriber::genTable.
   *
   * @param context The subscriber context.
   * @param db_interface A database interface.
   * @param callback A callback encapsulating Row yield method.
   * @param start_time Inclusive lower bound time limit.
   * @param end_time Inclusive upper bound time limit.
   * @param last_eid (optional) The last visited event id.
   * @return The upper bound time or 0 if there were no events in the range.
   */
  static EventIndex::iterator generateRows(Context& context,
                                           IDatabaseInterface& db_interface,
                                           std::function<void(Row)> callback,
                                           EventTime start_time,
                                           EventTime end_time,
                                           EventID last_eid = 0);

  explicit EventSubscriberPlugin(EventSubscriberPlugin const&) = delete;
  EventSubscriberPlugin& operator=(EventSubscriberPlugin const&) = delete;

  /// Trampoline into the EventFactory and lookup the name of the publisher.
  virtual const std::string& getType() const = 0;

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
  virtual const std::string dbNamespace() const;

  /// Return the current time (included to assist testing).
  virtual uint64_t getTime() const;

  /// Return the backing storage (included to assist testing).
  virtual IDatabaseInterface& getDatabase() const;

  /// Get a handle to the EventPublisher.
  EventPublisherRef getPublisher() const;

  /// Remove all subscriptions from this subscriber.
  void removeSubscriptions();

  /// Set the subscriber type and name on the managed context.
  void setDatabaseNamespace();

  /// A helper value counting the number of fired events tracked by publishers.
  EventContextID event_count_{0};

  /// A helper value counting the number of subscriptions created.
  size_t subscription_count_{0};

 private:
  Status setUp() override;

  /// Do not respond to periodic/scheduled/triggered event expiration requests.
  bool expire_events_{true};

  /// The minimum acceptable expiration, based on the query schedule.
  std::atomic<size_t> min_expiration_{0};

  /// The number of scheduled queries using this subscriber.
  std::atomic<size_t> query_count_{0};

  /// Set of queries that have used this subscriber table.
  std::map<std::string, uint64_t> queries_;

  /// Lock used when incrementing the EventID database index.
  Mutex event_id_lock_;

  /// Lock used when recording an EventID and time into search bins.
  Mutex event_record_lock_;

  /// Lock used when recording queries executing against this subscriber.
  mutable Mutex event_query_record_;

  Context context;

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

  friend class EventFactory;
  friend class EventPublisherPlugin;

  FRIEND_TEST(EventsTests, test_event_subscriber_configure);
  FRIEND_TEST(EventsTests, test_event_toggle_subscribers);
  FRIEND_TEST(EventSubscriberPluginTests, getExpireTime);
  FRIEND_TEST(EventSubscriberPluginTests, getEventsExpiry);
  FRIEND_TEST(EventSubscriberPluginTests, generateRowsWithExpiry);
  FRIEND_TEST(EventSubscriberPluginTests, generateRowsWithOptimize);

  friend class DBFakeEventSubscriber;
  friend class BenchmarkEventSubscriber;
};
} // namespace osquery
