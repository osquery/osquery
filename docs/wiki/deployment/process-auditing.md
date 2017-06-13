Process auditing is available in osquery, but requires additional configuration. It uses the same event-based architecture as the [File Integrity Monitoring (FIM)](../deployment/file-integrity-monitoring.md). To read more about how event-based tables are created and designed, check out the osquery [Table Pubsub Framework](../development/pubsub-framework.md). On all supported platforms, process events are abstracted into [`process_events`](https://osquery.io/docs/tables/#process_events). This table abstracts the basic details about process creation. Process state changes and destruction is not yet represented, nor planned.

To collect process events add a query like:
```
SELECT * FROM process_events;
```
to your query schedule, or to a query pack.

## Linux process auditing

osquery can use Linux Audit on the supported Linux distributions. This does NOT require any audit configuration or `auditd`; actually, auditd should not be running if using osquery's process auditing.

This creates a bit of confusion since audit, auditd, and libaudit are ambiguous-- osquery only uses the audit features in the kernel. Most distributions do not install libaudit or auditd, this is perfectly fine. If you are configuring audit, using a control binary, or `/etc/audit.conf`, your osquery *may* override your settings.

How does this work? Let's walk through 3 configuration options. These can be set at the [command line](../installation/cli-flags.md), or via the configuration's options. 

1. `--disable_audit=false` by default this is set to `true` and prevents osquery from opening the kernel audit's netlink socket. 
2. `--audit_allow_config=true` by default this is set to `false` and prevents osquery from making audit configuration changes. These changes include adding/removing rules, setting the global enable flags, and adjusting performance and rate parameters.
3. `--audit_persist=true` but default this is `true` and instructs osquery to 'regain' the audit netlink socket if another process also accesses it.

On Linux a companion table `user_events` is included that provides several authentication-based events. If you are enabling process auditing it should be trivial to also include this table.

#### Linux socket auditing

Another audit-based table is provided on Linux: `socket_events`. This table reports events for the syscalls `bind` and `connect`. This table is not enabled with process events by default because it introduces considerable added load on the system.

Use `--audit_allow_sockets` to enable the associated event subscriber.

## macOS process auditing

osquery does not (yet?) support audit on Darwin platforms. It is possible to enable process auditing using a kernel extension. The extension can be downloaded and installed from the [http://osquery.io/downloads](http://osquery.io/downloads) page. It must be kept up to date alongside the osquery daemon and shell since there are automatic API restrictions applied. If you are running a 1.7.5 daemon, a 1.7.5 extension is needed otherwise the extension will not be used. If you are interested in the extension's design and development please check out the [kernel](../development/kernel.md) development guide.

At the heart of the extension is a replica of the userland Table Pubsub Framework. All osquery-developed kernel code is 100% OS public API compatible and designed to introduce as little stability risk as possible. Running the kernel extension without the osquery daemon should not impact performance.

There are no configuration or additional options required to enable process auditing on macOS if the kernel extension is installed. The osquery daemon will auto-detect the extension and attempt to load and connect when the process starts.

## osquery events optimization

This section provides a brief overview of common and recommended optimizations for event-based tables. These optimizations also apply to the FIM events.

1. `--events_optimize=true` apply optimizations when `SELECT`ing from events-based tables, default enabled. 
2. `--events_expiry` the lifetime of buffered events in seconds, default 86000.
3. `--events_max` the maximum number of events to buffer, default 1000.

The goal of optimizations are to protect the running process and system from impacting performance. By default these are all enabled, which is good for configuration and performance, but may introduce inconsistencies on highly-stressed systems using process auditing.

Optimizations work best when `SELECT`ing often from event-based tables. Otherwise the events are in a buffered state. When an event-based table is selected within the daemon, the backing storage maintaining event data is cleared according to the `--event_expiry` lifetime. Setting this value to `1` will auto-clear events event select, reducing all impact of the buffer.
