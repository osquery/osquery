# The pub-sub evented data framework of osquery

Most of osquery's virtual tables are generated when an SQL statement requests data. For example, the [time](https://github.com/osquery/osquery/blob/master/osquery/tables/utility/time.cpp) gets the current time and returns it as a single row. So whenever a call selects data from time, e.g., `SELECT * FROM time;` the current time of the call will return.

From an operating systems perspective, query-time synchronous data retrieval is lossy. Consider the [processes](https://github.com/osquery/osquery/blob/master/osquery/tables/system/linux/processes.cpp) table: if a process like `ps` runs for a fraction of a moment there's no way `SELECT * FROM processes;` will ever include the details.

To solve this, osquery exposes a [pubsub framework](https://github.com/osquery/osquery/tree/master/osquery/events) for aggregating operating system information asynchronously at event time, storing related event details in the osquery backing store, and performing a lookup to report stored rows query time. This reporting pipeline is much more complicated than typical query-time virtual table generation. The time of event, storage history, and applicable (final) virtual table data information must be carefully considered. As events occur, the rows returned by a query will compound, as such selecting from an event-based virtual table generator should always include a time range.

If no time range is provided, as in: `SELECT * FROM process_events;`, it is assumed you want to scan from `t=[0, now)`. Otherwise, all of the `*_events` tables must have a `time` column, this is used to optimize searching: `SELECT * FROM process_events WHERE time > NOW() - 300;`.

## Query and table usage

Every pubsub-based table ends with `_events`. These tables will perform lookups into the osquery backing storage: RocksDB, for events buffered by the subscribers. These tables are a "query-time" abstraction that allow you to use SQL aggregations and a `time` column for optimizing lookups.

When using the `osqueryi` shell, these tables will mostly remain empty. This is because the event loops start and stop with the process. If the shell is not running, no events are being buffered. Furthermore, some of the APIs used by the runloops require super-user privileges or non-default flags and options. The shell does **not** communicate with the osquery daemon, nor does it use the same RocksDB storage. Thus the shell cannot be used to explore events buffered by the daemon.

The buffered events will eventually expire! The `--events_expiry` flag controls the lifetime of buffered events. This is set to 1 day by default, this expiration occurs when events are selected from their subscriber table. For example: the `process_events` subscriber will buffer process starts until a query selects from this table. At that point all results will be returned and immediately after, any event that happened `time-86400` seconds ago will be deleted. If you select from this table every second you will constantly see a window of 1 day's worth of process events.

When scheduling queries that include `_events` (subscriber-based) tables, additional optimizations are invoked. These optimization can be disabled using `--events_optimize=false`. The subscriber tables can detect they are responding to a schedule and may keep track of the last time the scheduled query has executed. This allows each subscriber to return the exact window of the schedule and delete buffered events immediately. This saves the most memory and disk usage possible while still allowing flexible scheduling.

## Architecture

An osquery event publisher is a combination of a threaded run loop and event storage abstraction. The publisher loops on some selected resource or uses operating system APIs to register callbacks. The loop or callback introspects on the event and sends it to every appropriate subscriber. An osquery event subscriber will send subscriptions to a publisher, save published data, and react to a query by returning appropriate data.

The pubsub runflow is exposed as a publisher `setUp()`, a series of `addSubscription(const SubscriptionRef)` by subscribers, a publisher `configure()`, and finally a new thread scheduled with the publisher's `run()` static method as the entry point. For every event the publisher receives it will loop through every `Subscription` and call `fire(const EventContextRef, EventTime)` to send the event to the subscriber.

## Example: inotify

Filesystem events are the simplest example. Let's consider Linux's inotify framework: [osquery/events/linux/inotify.cpp](https://github.com/osquery/osquery/blob/master/osquery/events/linux/inotify.cpp) implements an osquery publisher.

There's a list of yet-to-be-implemented uses of the inotify publisher, but a simple example includes querying for every change to `/etc/passwd`. The [osquery/tables/events/linux/file_events.cpp](https://github.com/osquery/osquery/blob/master/osquery/tables/events/linux/file_events.cpp) table uses a pubsub subscription and implements a subscriber. The subscriptions are constructed from the configuration. See the file [integrity monitoring deployment](../deployment/file-integrity-monitoring.md) guide for details.

## Event Subscribers

Let's continue to use the inotify event publisher as an example. And let's implement a table that reports new files created in `/etc/`. The first thing we need is a [table spec](creating-tables.md):

```python
table_name("new_etc_files")
schema([
    Column("path", TEXT),
    Column("time", TEXT),
])
implementation("new_etc_files@NewETCFilesEventSubscriber::genTable")
```

Now with the simplest table spec possible, we need to write `NewETCFilesEventSubscriber`!

```cpp
#include <osquery/database/database.h>
#include <osquery/events/linux/inotify.h>

namespace osquery {
namespace tables {

class NewETCFilesEventSubscriber : public EventSubscriber<INotifyEventPublisher> {
 public:
  // Implement the pure virtual init interface.
  Status init() override;
};
```

Done! Well, not exactly. This subscriber will do nothing since it hasn't given the publisher a subscription nor set up a callback to save appropriate events. To create a subscription we must know more about the publisher, for inotify we must create a [`INotifySubscriptionContext`](https://github.com/osquery/osquery/blob/master/osquery/events/linux/inotify.h) then subscribe to the publisher using this context and a callback.

Let's implement `NewETCFilesEventSubscriber::init()` to add the subscription:

```cpp
Status NewETCFilesEventSubscriber::init() {
  // We templated our subscriber to create an inotify publisher-specific
  // subscription context.
  auto sc = createSubscriptionContext();
  sc->path = "/etc";
  sc->recursive = true;
  // 'mask' is specific to inotify.
  sc->mask = IN_CREATE;
  subscribe(&NewETCFilesEventSubscriber::Callback, sc);
}
```

The final line in `init()` binds the subscription context to a callback, which we haven't defined or implemented. Let's modify the subscriber to include this callback:

```cpp
class NewETCFilesEventSubscriber : public EventSubscriber<INotifyEventPublisher> {
 public:
  Status init() override;
  Status Callback(const ECRef& ec, const SCRef& sc);
};

REGISTER(NewETCFilesEventSubscriber, "event_subscriber", "new_etc_files");
```

Now the call to `subscribe` is meaningful: If the publisher generates an event and if the event details match the subscription request details, or new files all subfolders within "/etc", `Callback` will _fire_.

Finally, we must implement the callback. The callback is responsible for turning the event information into an osquery `Row` data structure and saving that to the backing store (RocksDB). Such that, at query time the rows can be fetched and returned to the caller.

```cpp
Status NewETCFilesEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  Row r;
  r["path"] = ec->path;
  r["time"] = ec->time_string;
  add(r, ec->time);
  return Status(0, "OK");
}
```

Simple. Notice that `ec->time_string` provides a string-formatted time that eliminates the need for casting.
