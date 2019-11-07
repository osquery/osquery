/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <chrono>
#include <exception>
#include <thread>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/lexical_cast.hpp>
#include <conveyor.h>

#include <osquery/config/config.h>
#include <osquery/database.h>
#include <osquery/events.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>
#include <osquery/sql.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/system.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/system/time.h>

#include "./stringmap_encoder.hpp"

namespace osquery {

CREATE_REGISTRY(EventPublisherPlugin, "event_publisher");
CREATE_REGISTRY(EventSubscriberPlugin, "event_subscriber");

/// Checkpoint interval to inspect max event buffering.
#define EVENTS_CHECKPOINT 256

FLAG(bool, disable_events, false, "Disable osquery publish/subscribe system");

FLAG(bool,
     events_optimize,
     true,
     "Always true. Flag remains for command-line compatibility");

HIDDEN_FLAG(bool, events_debug, false, "");

#define DBGLOG                                                                 \
  if (FLAGS_events_debug)                                                      \
  LOG(INFO)

// Access this flag through EventSubscriberPlugin::getEventsExpiry to allow for
// overriding in subclasses
FLAG(uint64,
     events_expiry,
     3600,
     "Command-line only: Timeout to expire event"
     " subscriber results."
     " In daemon mode, all SELECT and JOIN queries using an event table must "
     "have"
     " the same interval, and event records are automatically be expired after "
     "all"
     " queries have seen them once.");

// Access this flag through EventSubscriberPlugin::getEventsMax to allow for
// overriding in subclasses
FLAG(uint64, events_max, 50000, "Maximum number of events per type to buffer");

DECLARE_string(database_path);

struct IntervalCursorState {
  size_t interval;
  uint32_t num_queries;
  uint32_t num_get_calls;
  SPFileCursor cursor;
};

static inline EventTime timeFromRecord(const std::string& record) {
  // Convert a stored index "as string bytes" to a time value.
  return static_cast<EventTime>(tryTo<long long>(record).takeOr(0ll));
}

static const ScheduledQuery* gActiveQuery = nullptr;
void EventFactory::_setActiveSchedulerQuery(const ScheduledQuery* pquery) { gActiveQuery = pquery; }

void EventSubscriberPlugin::genTable(RowYield& yield, QueryContext& context) {
  // Stop is an unsigned (-1), our end of time equivalent.
  EventTime start = 0, stop = 0;
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
  } else if (Initializer::isDaemon()) {
    // If the daemon is querying a subscriber without a 'time' constraint and
    // allows optimization, only emit events since the last query.
    // conveyor_ takes care of the details based on query_count_ and get_calls_
  }
  get(yield, start, stop);
}

EventContextID EventPublisherPlugin::numEvents() const {
  return next_ec_id_.load();
}

size_t EventPublisherPlugin::numSubscriptions() {
  ReadLock lock(subscription_lock_);
  return subscriptions_.size();
}

void EventSubscriberPlugin::_initPrivateState() {
  auto expiry = FLAGS_events_expiry;
  if (Initializer::isDaemon()) {
    // conveyor expiry is automatic based on interval cursors
    // only use expiry as a fallback (60 minutes)
    expiry = 3600;
  }
  if (conveyor_void_ == nullptr) {
    auto path = boost::filesystem::path(FLAGS_database_path) / "events";
    path.make_preferred(); // for windows path seperators
    createDirectory(path);
    const ConveyorSettings settings = {path.string(),
                                       dbNamespace(),
                                       5 /* files */,
                                       (uint32_t)FLAGS_events_max,
                                       (uint32_t)(expiry),
                                       16 * 1024 * 1024 /* max record size*/};
    conveyor_void_ = ConveyorNew(settings);
    columns_hasher_void_ = std::make_shared<StringHash>();
    interval_cursor_map_ = std::map<size_t, std::shared_ptr<void>>();

    if (conveyor_void_ != nullptr) {
      auto conveyor_ = std::static_pointer_cast<Conveyor>(conveyor_void_);
      conveyor_->deleteAndStartFresh();
      // TODO: clear or load stored events?
      // conveyor_->loadPersistedState();
    }
  }
}

void EventPublisherPlugin::fire(const EventContextRef& ec, EventTime time) {
  if (isEnding()) {
    // Cannot emit/fire while ending
    return;
  }

  EventContextID ec_id = 0;
  ec_id = next_ec_id_.fetch_add(1);

  // Fill in EventContext ID and time if needed.
  if (ec != nullptr) {
    ec->id = ec_id;
    if (ec->time == 0) {
      if (time == 0) {
        time = getUnixTime();
      }
      ec->time = time;
    }
  }

  ReadLock lock(subscription_lock_);
  for (const auto& subscription : subscriptions_) {
    auto es = EventFactory::getEventSubscriber(subscription->subscriber_name);
    if (es != nullptr && es->state() == EventState::EVENT_RUNNING) {
      fireCallback(subscription, ec);
    }
  }
}

size_t EventSubscriberPlugin::getEventsExpiry() {
  return FLAGS_events_expiry;
}

size_t EventSubscriberPlugin::getEventsMax() {
  return FLAGS_events_max;
}

inline std::string debug_serialize_row(const Row& r) {
  std::string s;
  for (auto it : r) {
    s += it.first + ":" + it.second + ", ";
  }
  return s;
}

struct MyConveyorListener : public ConveyorListener {
  MyConveyorListener(RowYield& yield,
                     EventTime start,
                     EventTime stop,
                     std::string dbns)
      : yield_(yield), start_(start), stop_(stop), namespace_(dbns) {
    isCommandLineMode = !Initializer::isDaemon();
  }
  virtual ~MyConveyorListener() {}

  void onRecord(void* context,
                const std::string& value,
                std::time_t ts,
                uint32_t id) override {
    Row r;
    // VLOG(1) << "onRecord len:" << value.length() << " id:" << id;

    if (value.length() == 0) {
      return;
    }

    // honor time-based queries in command-line mode

    if (isCommandLineMode && (start_ != 0 || stop_ != 0)) {
      if ((EventTime)ts < start_ || (EventTime)ts > stop_) {
        DBGLOG << namespace_
               << " skipping event based on time range. start:" << start_
               << " stop:" << stop_;
        return;
      }
    }

    if (StringMapCoder::decode(r, value, lastKeyHash_)) {
      LOG(WARNING) << namespace_ << " failed to deserialize event. id:" << id;
      return;
    }

    DBGLOG << namespace_ << " yield id: " << id
           << " row: " << debug_serialize_row(r);

    yield_(TableRowHolder(new DynamicTableRow(std::move(r))));
  }

  RowYield& yield_;
  EventTime start_;
  EventTime stop_;
  bool isCommandLineMode;
  uint32_t lastKeyHash_{0};
  std::string namespace_;
};

static void trackDropStats(size_t numRecords, int status, EventPubStats& stats);
static bool shouldLogDropStats(EventPubStats& stats);

void EventSubscriberPlugin::get(RowYield& yield,
                                EventTime start,
                                EventTime stop) {
  if (conveyor_void_ == nullptr) {
    LOG(WARNING) << "event subscriber private state not set";
    return;
  }

  if (shouldLogDropStats(stats_)) {
    LOG(WARNING) << "STATS " << dbNamespace() << " events:" << stats_.numEvents
                 << " drops:" << stats_.numDrops
                 << " writeErrs:" << stats_.numWriteErrors;
  }

  bool cleanupRecords = true;
  bool isTrackedIntervalQuery = false;
  auto conveyor_ = std::static_pointer_cast<Conveyor>(conveyor_void_);
  SPFileCursor cursor;

  if (!Initializer::isDaemon()) {
    // when running from cmdline, we don't have a fixed number of queries
    // hitting this table, so we can't determine when to expire.  User must
    // provide timestamps constraint.  Additionally, cleanup will happen for
    // expired records as they are seen.
    cleanupRecords = false;
    cursor = conveyor_->openCursor();
  } else {
    // Advance cursor after all queries on main_interval_ have been run once.

    auto pQuery = gActiveQuery;

    auto fit = interval_cursor_map_.find(pQuery->interval);
    if (fit == interval_cursor_map_.end()) {
      // not a scheduled query
      cursor = conveyor_->openCursor();
    } else {
      isTrackedIntervalQuery = true;
      auto spState = std::static_pointer_cast<IntervalCursorState>(fit->second);
      cleanupRecords = ((spState->num_get_calls % spState->num_queries) ==
                        (spState->num_queries - 1));
      spState->num_get_calls++;
      cursor = spState->cursor;
      DBGLOG << dbNamespace() << " query_count_:" << spState->num_queries;
    }
  }

  MyConveyorListener myListener(yield, start, stop, dbNamespace());
  conveyor_->enumerateRecords(myListener, nullptr, cursor, std::time(NULL));
  if (cleanupRecords) {
    conveyor_->advanceCursor(cursor);
    conveyor_->persistState();
    DBGLOG << dbNamespace()
           << " cursor advanced start.id:" << cursor->getStart().id
           << " end.id:" << cursor->getEnd().id;
  }
}

Status EventSubscriberPlugin::add(const Row& row) {
  auto conveyor_ = std::static_pointer_cast<Conveyor>(conveyor_void_);
  auto columns_hasher_ =
      std::static_pointer_cast<StringHash>(columns_hasher_void_);

  DBGLOG << dbNamespace() << " .add() s:" << debug_serialize_row(row);

  event_count_++;

  std::string serialized_row;
  if (StringMapCoder::encode(row, serialized_row, *columns_hasher_)) {
    Status status = Status(1, "failed to encode event cache row");
    VLOG(1) << status.getMessage();
    return status;
  }

  int rv = 0;
  if (nullptr != conveyor_) {
    rv = conveyor_->addRecord(serialized_row, std::time(NULL));
    trackDropStats(1, rv, stats_);
  }
  return Status(rv);
}

Status EventSubscriberPlugin::addBatch(std::vector<Row>& row_list) {
  return addBatch(row_list, getUnixTime());
}

Status EventSubscriberPlugin::addBatch(std::vector<Row>& row_list,
                                       EventTime custom_event_time) {
  DBGLOG << dbNamespace() << " subplugin.addBatch()";

  std::vector<std::string> serialized;
  serialized.reserve(row_list.size());

  auto event_time = custom_event_time != 0 ? custom_event_time : getUnixTime();
  auto event_time_str = std::to_string(event_time);

  auto conveyor_ = std::static_pointer_cast<Conveyor>(conveyor_void_);
  auto columns_hasher_ =
      std::static_pointer_cast<StringHash>(columns_hasher_void_);
  if (conveyor_ == nullptr) {
    return Status(0);
  }

  for (auto& row : row_list) {
    if (row.empty()) {
      continue;
    }

    row["time"] = event_time_str;

    // Serialize and store the row data, for query-time retrieval.
    std::string serialized_row;
    if (StringMapCoder::encode(row, serialized_row, *columns_hasher_)) {
      Status status = Status(1, "failed to encode event cache row");
      VLOG(1) << status.getMessage();
      continue;
    }
    if (serialized_row.empty()) {
      VLOG(1) << "serialized row is empty";
      continue;
    }

    // Logger plugins may request events to be forwarded directly.
    // If no active logger is marked 'usesLogEvent' then this is a no-op.
    EventFactory::forwardEvent(serialized_row);

    serialized.push_back(serialized_row);
    event_count_++;
  }

  if (serialized.empty()) {
    return Status(1, "Failed to process the rows");
  }

  // Save the batched data inside the database
  int rv = conveyor_->addBatch(serialized, std::time(NULL));
  trackDropStats(serialized.size(), rv, stats_);

  return Status(rv);
}

EventPublisherRef EventSubscriberPlugin::getPublisher() const {
  return EventFactory::getEventPublisher(getType());
}

void EventSubscriberPlugin::removeSubscriptions() {
  subscription_count_ = 0;
  auto publisher = getPublisher();
  if (publisher == nullptr) {
    LOG(WARNING) << "Cannot remove subscriptions from: " << getName();
    return;
  }

  getPublisher()->removeSubscriptions(getName());
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
      auto thread_ = std::make_shared<std::thread>(
          std::bind(&EventFactory::run, publisher.first));
      ef.threads_.push_back(thread_);
    }
  }
}

Status EventPublisherPlugin::addSubscription(
    const SubscriptionRef& subscription) {
  // The publisher threads may be running and if they fire events the list of
  // subscriptions will be walked.
  WriteLock lock(subscription_lock_);
  subscriptions_.push_back(subscription);
  return Status(0);
}

void EventPublisherPlugin::removeSubscriptions(const std::string& subscriber) {
  // See addSubscription for details on the critical section.
  WriteLock lock(subscription_lock_);
  auto end =
      std::remove_if(subscriptions_.begin(),
                     subscriptions_.end(),
                     [&subscriber](const SubscriptionRef& subscription) {
                       return (subscription->subscriber_name == subscriber);
                     });
  subscriptions_.erase(end, subscriptions_.end());
}

void EventFactory::addForwarder(const std::string& logger) {
  getInstance().loggers_.push_back(logger);
}

void EventFactory::forwardEvent(const std::string& event) {
  for (const auto& logger : getInstance().loggers_) {
    Registry::call("logger", logger, {{"event", event}});
  }
}

void EventSubscriberPlugin::analyzeIntervals(
    const std::map<size_t, std::vector<std::string>>& qimap) {
  auto conveyor_ = std::static_pointer_cast<Conveyor>(conveyor_void_);

  if (qimap.size() == 0) {
    return; // should never happen
  }

  // cleanup and close existing cursors
  for (auto it : interval_cursor_map_) {
    auto spState = std::static_pointer_cast<IntervalCursorState>(it.second);
    conveyor_->closeCursor(spState->cursor);
  }

  interval_cursor_map_.clear();

  for (auto it : qimap) {
    auto interval = it.first;
    interval_cursor_map_[interval] = std::make_shared<IntervalCursorState>();
    auto stateObj = std::static_pointer_cast<IntervalCursorState>(
        interval_cursor_map_[interval]);
    stateObj->interval = interval;
    stateObj->num_queries = (uint32_t)it.second.size();
    stateObj->cursor = conveyor_->openCursor();
    VLOG(1) << dbNamespace() << " has " << stateObj->num_queries
            << " queries at interval:" << interval
            << (interval > 300 ? " ( LONG )" : "");

    // TODO: remove the need for min_expiration_

    min_expiration_ = interval * 3;
    min_expiration_ += (60 - (min_expiration_ % 60));
  }
}

void EventFactory::configUpdate() {
  // Scan the schedule for queries that touch "_events" tables.
  // We will count the queries
  std::map<std::string, SubscriberExpirationDetails> subscriber_details;
  Config::get().scheduledQueries(
      [&subscriber_details](std::string name, const ScheduledQuery& query) {
        std::vector<std::string> tables;
        // Convert query string into a list of virtual tables effected.
        if (!getQueryTables(query.query, tables)) {
          VLOG(1) << "Cannot get tables from query: " << name;
          return;
        }

        // Remove duplicates and select only the subscriber tables.
        std::set<std::string> subscribers;
        for (const auto& table : tables) {
          if (Registry::get().exists("event_subscriber", table)) {
            subscribers.insert(table);
          }
        }

        for (const auto& subscriber : subscribers) {
          auto& details = subscriber_details[subscriber];
          if (details.query_interval_map.count(query.interval) == 0) {
            details.query_interval_map[query.interval] =
                std::vector<std::string>();
          }
          details.query_interval_map[query.interval].push_back(name);
        }
      });

  auto& ef = EventFactory::getInstance();
  for (const auto& details : subscriber_details) {
    if (!ef.exists(details.first)) {
      continue;
    }

    RecursiveLock lock(ef.factory_lock_);
    auto subscriber = ef.getEventSubscriber(details.first);

    subscriber->analyzeIntervals(details.second.query_interval_map);
  }

  // If events are enabled configure the subscribers before publishers.
  if (!FLAGS_disable_events) {
    RegistryFactory::get().registry("event_subscriber")->configure();
    RegistryFactory::get().registry("event_publisher")->configure();
  }
}

Status EventFactory::run(const std::string& type_id) {
  if (FLAGS_disable_events) {
    return Status(0, "Events disabled");
  }

  // An interesting take on an event dispatched entrypoint.
  // There is little introspection into the event type.
  // Assume it can either make use of an entrypoint poller/selector or
  // take care of async callback registrations in setUp/configure/run
  // only once and handle event queuing/firing in callbacks.
  EventPublisherRef publisher = nullptr;
  {
    auto& ef = EventFactory::getInstance();
    RecursiveLock lock(ef.factory_lock_);
    publisher = ef.getEventPublisher(type_id);
  }

  if (publisher == nullptr) {
    return Status(1, "Event publisher is missing");
  } else if (publisher->hasStarted()) {
    return Status(1, "Cannot restart an event publisher");
  }
  setThreadName(publisher->name());
  VLOG(1) << "Starting event publisher run loop: " + type_id;
  publisher->hasStarted(true);

  auto status = Status(0, "OK");
  while (!publisher->isEnding()) {
    // Can optionally implement a global cooloff latency here.
    status = publisher->run();
    if (!status.ok()) {
      break;
    }
    publisher->restart_count_++;
    // This is a 'default' cool-off implemented in InterruptableRunnable.
    // If a publisher fails to perform some sort of interruption point, this
    // prevents the thread from thrashing through exiting checks.
    publisher->pause(std::chrono::milliseconds(200));
  }
  if (!status.ok()) {
    // The runloop status is not reflective of the event type's.
    VLOG(1) << "Event publisher " << publisher->type()
            << " run loop terminated for reason: " << status.getMessage();
    // Publishers auto tear down when their run loop stops.
  }
  publisher->tearDown();
  publisher->state(EventState::EVENT_NONE);

  // Do not remove the publisher from the event factory.
  // If the event factory's `end` method was called these publishers will be
  // cleaned up after their thread context is removed; otherwise, a removed
  // thread context and failed publisher will remain available for stats.
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
  } catch (const std::bad_cast& /* e */) {
    return Status(1, "Incorrect plugin");
  }

  if (specialized_pub == nullptr || specialized_pub.get() == nullptr) {
    return Status(0, "Invalid publisher");
  }

  auto type_id = specialized_pub->type();
  if (type_id.empty()) {
    // This subscriber did not override its name.
    return Status(1, "Publishers must have a type");
  }

  auto& ef = EventFactory::getInstance();
  {
    RecursiveLock lock(getInstance().factory_lock_);
    if (ef.event_pubs_.count(type_id) != 0) {
      // This is a duplicate event publisher.
      return Status(1, "Duplicate publisher type");
    }

    ef.event_pubs_[type_id] = specialized_pub;
  }

  // Do not set up event publisher if events are disabled.
  if (!FLAGS_disable_events) {
    if (specialized_pub->state() != EventState::EVENT_NONE) {
      specialized_pub->tearDown();
    }

    auto status = specialized_pub->setUp();
    specialized_pub->state(EventState::EVENT_SETUP);
    if (!status.ok()) {
      // Only start event loop if setUp succeeds.
      LOG(INFO) << "Event publisher not enabled: " << type_id << ": "
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
  } catch (const std::bad_cast& /* e */) {
    return Status(1, "Incorrect plugin");
  }

  if (specialized_sub == nullptr || specialized_sub.get() == nullptr) {
    return Status(1, "Invalid subscriber");
  }

  // The config may use an "events" key to explicitly enabled or disable
  // event subscribers. See EventSubscriber::disable.
  auto name = specialized_sub->getName();
  if (name.empty()) {
    // This subscriber did not override its name.
    return Status(1, "Subscribers must have set a name");
  }

  auto plugin = Config::get().getParser("events");
  if (plugin != nullptr && plugin.get() != nullptr) {
    const auto& data = plugin->getData().doc();
    // First perform explicit enabling.
    if (data["events"].HasMember("enable_subscribers")) {
      for (const auto& item : data["events"]["enable_subscribers"].GetArray()) {
        if (item.GetString() == name) {
          VLOG(1) << "Enabling event subscriber: " << name;
          specialized_sub->disabled = false;
        }
      }
    }
    // Then use explicit disabling as an ultimate override.
    if (data["events"].HasMember("disable_subscribers")) {
      for (const auto& item :
           data["events"]["disable_subscribers"].GetArray()) {
        if (item.GetString() == name) {
          VLOG(1) << "Disabling event subscriber: " << name;
          specialized_sub->disabled = true;
        }
      }
    }
  }

  if (specialized_sub->state() != EventState::EVENT_NONE) {
    specialized_sub->tearDown();
  }

  // Allow subscribers a configure-time setup to determine if they should run.
  auto status = specialized_sub->setUp();
  if (!status) {
    specialized_sub->disabled = true;
  }
  specialized_sub->state(EventState::EVENT_SETUP);

  // Let the subscriber initialize any Subscriptions.
  if (!FLAGS_disable_events && !specialized_sub->disabled) {
    status = specialized_sub->init();

    specialized_sub->_initPrivateState();

    specialized_sub->state(EventState::EVENT_RUNNING);
  } else {
    specialized_sub->state(EventState::EVENT_PAUSED);
  }

  auto& ef = EventFactory::getInstance();
  {
    RecursiveLock lock(getInstance().factory_lock_);
    ef.event_subs_[name] = specialized_sub;
  }

  // Set state of subscriber.
  if (!status.ok()) {
    specialized_sub->state(EventState::EVENT_FAILED);
    return Status(1, status.getMessage());
  } else {
    return Status(0, "OK");
  }
}

Status EventFactory::addSubscription(const std::string& type_id,
                                     const std::string& name_id,
                                     const SubscriptionContextRef& mc,
                                     EventCallback cb) {
  auto subscription = Subscription::create(name_id, mc, cb);
  return EventFactory::addSubscription(type_id, subscription);
}

Status EventFactory::addSubscription(const std::string& type_id,
                                     const SubscriptionRef& subscription) {
  EventPublisherRef publisher = getInstance().getEventPublisher(type_id);
  if (publisher == nullptr) {
    return Status(1, "Unknown event publisher");
  }

  // The event factory is responsible for configuring the event types.
  return publisher->addSubscription(subscription);
}

size_t EventFactory::numSubscriptions(const std::string& type_id) {
  EventPublisherRef publisher;
  try {
    publisher = EventFactory::getInstance().getEventPublisher(type_id);
  } catch (std::out_of_range& /* e */) {
    return 0;
  }
  if (publisher == nullptr) {
    return 0;
  }
  return publisher->numSubscriptions();
}

EventPublisherRef EventFactory::getEventPublisher(const std::string& type_id) {
  if (getInstance().event_pubs_.count(type_id) == 0) {
    LOG(ERROR) << "Requested unknown/failed event publisher: " + type_id;
    return nullptr;
  }
  return getInstance().event_pubs_.at(type_id);
}

EventSubscriberRef EventFactory::getEventSubscriber(
    const std::string& name_id) {
  if (!exists(name_id)) {
    LOG(ERROR) << "Requested unknown event subscriber: " + name_id;
    return nullptr;
  }
  return getInstance().event_subs_.at(name_id);
}

bool EventFactory::exists(const std::string& name_id) {
  return (getInstance().event_subs_.count(name_id) > 0);
}

Status EventFactory::deregisterEventPublisher(const EventPublisherRef& pub) {
  return EventFactory::deregisterEventPublisher(pub->type());
}

Status EventFactory::deregisterEventPublisher(const std::string& type_id) {
  auto& ef = EventFactory::getInstance();

  RecursiveLock lock(ef.factory_lock_);
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
      publisher->state(EventState::EVENT_NONE);
      // If the run loop did run the tear down and erase will happen in the
      // event thread wrapper when isEnding is next checked.
      ef.event_pubs_.erase(type_id);
    } else {
      publisher->stop();
    }
  }
  return Status(0, "OK");
}

Status EventFactory::deregisterEventSubscriber(const std::string& sub) {
  auto& ef = EventFactory::getInstance();

  RecursiveLock lock(ef.factory_lock_);
  if (ef.event_subs_.count(sub) == 0) {
    return Status(1, "Event subscriber is missing");
  }

  auto& subscriber = ef.event_subs_.at(sub);
  subscriber->state(EventState::EVENT_NONE);
  subscriber->tearDown();
  ef.event_subs_.erase(sub);
  return Status(0);
}

std::vector<std::string> EventFactory::publisherTypes() {
  RecursiveLock lock(getInstance().factory_lock_);
  std::vector<std::string> types;
  for (const auto& publisher : getInstance().event_pubs_) {
    types.push_back(publisher.first);
  }
  return types;
}

std::vector<std::string> EventFactory::subscriberNames() {
  RecursiveLock lock(getInstance().factory_lock_);
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

  {
    RecursiveLock lock(getInstance().factory_lock_);
    // A small cool off helps OS API event publisher flushing.
    if (!FLAGS_disable_events) {
      ef.threads_.clear();
    }

    // Threads may still be executing, when they finish, release publishers.
    ef.event_pubs_.clear();
    ef.event_subs_.clear();
  }
}

void attachEvents() {
  const auto& publishers = RegistryFactory::get().plugins("event_publisher");
  for (const auto& publisher : publishers) {
    EventFactory::registerEventPublisher(publisher.second);
  }

  const auto& subscribers = RegistryFactory::get().plugins("event_subscriber");
  for (const auto& subscriber : subscribers) {
    if (!boost::ends_with(subscriber.first, "_events")) {
      LOG(ERROR) << "Error registering subscriber: " << subscriber.first
                 << ": Must use a '_events' suffix";
      continue;
    }

    auto status = EventFactory::registerEventSubscriber(subscriber.second);
    if (!status.ok()) {
      VLOG(1) << "Error registering subscriber: " << subscriber.first << ": "
              << status.getMessage();
    }
  }

  // Configure the event publishers and subscribers.
  EventFactory::configUpdate();
}

static const int DROP_STAT_INTERVAL_SECONDS = 5 * 60;

void trackDropStats(size_t numRecords, int status, EventPubStats& stats) {
  if (status == 0) {
    stats.numEvents += numRecords;
    return;
  }
  if (status < 0) {
    stats.numWriteErrors += numRecords;
    return;
  }

  size_t numDrops = status;
  if (numDrops > numRecords) {
    numDrops = numRecords;
  }
  size_t numEvents = numRecords - numDrops;
  stats.numEvents += numEvents;
  stats.numDrops += numDrops;
}

bool shouldLogDropStats(EventPubStats& stats) {
  bool shouldLog = false;
  time_t now = time(NULL);

  if (stats.lastTs == 0) {
    stats.lastTs = now;
    return false;
  }
  if ((now - stats.lastTs) < (time_t)DROP_STAT_INTERVAL_SECONDS) {
    return false;
  }

  // if drop stats has changed, log it
  stats.lastTs = now;
  if (stats.lastNumDrops != stats.numDrops ||
      stats.lastNumWriteErrors != stats.numWriteErrors) {
    shouldLog = true;
  }
  stats.lastNumDrops = stats.numDrops;
  stats.lastNumWriteErrors = stats.numWriteErrors;
  return shouldLog;
}

} // namespace osquery
