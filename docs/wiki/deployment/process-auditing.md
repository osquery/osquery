Process auditing is available in osquery, but requires additional configuration. It uses the same event-based architecture as the [File Integrity Monitoring (FIM)](../deployment/file-integrity-monitoring.md). To read more about how event-based tables are created and designed, check out the osquery [Table Pubsub Framework](../development/pubsub-framework.md). On all supported platforms, process events are abstracted into [`process_events`](https://osquery.io/schema/current/#process_events). This table abstracts the basic details about process creation. Process state changes and destruction is not yet represented, nor planned.

To collect process events add a query like:
```sql
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

If you would like to debug the audit logging use the hidden flag `--audit_debug`. This will print all of the RAW audit lines to osquery's stdout.

#### Linux socket auditing

Another audit-based table is provided on Linux: `socket_events`. This table reports events for the syscalls `bind` and `connect`. This table is not enabled with process events by default because it introduces considerable added load on the system.

Use `--audit_allow_sockets` to enable the associated event subscriber.

If you would like to log UNIX domain sockets use the hidden flag: `--audit_allow_unix`. This will put considerable strain on the system as many default actions use domain sockets. You will also need to explicitly select the `socket` column from the `socket_events` table.

## macOS process auditing

osquery has support for OpenBSM audit on Darwin platforms. This feature is already enabled on all macOS installations but doesn't audit process execution or the root user with default settings. To start process auditing on macOS, edit the `audit_control` file in `/etc/security/`. An example configuration is provided below but the important flags are: `ex`, `pc`, `argv`, and `arge`. The `ex` flag will log `exec` events while `pc` logs `exec`, `fork`, and `exit`. If you don't need `fork` and `exit` you may leave that flag out however in future, getting parent pid may require `fork`. If you care about getting the arguments and environment variables you also need `argv` and `arge`. More about these flags can be found [here](https://www.freebsd.org/cgi/man.cgi?apropos=0&sektion=5&query=audit_control&manpath=FreeBSD+7.0-current&format=html). Note that it might require a reboot of the system for these new flags to take effect. `audit -s` should restart the system but your mileage may vary.
```
#
# $P4: //depot/projects/trustedbsd/openbsm/etc/audit_control#8 $
#
dir:/var/audit
flags:ex,pc,ap,aa,lo,ad
minfree:5
naflags:no
policy:cnt,argv,arge
filesz:2M
expire-after:10M
superuser-set-sflags-mask:has_authenticated,has_console_access
superuser-clear-sflags-mask:has_authenticated,has_console_access
member-set-sflags-mask:
member-clear-sflags-mask:has_authenticated
```

## osquery events optimization

This section provides a brief overview of common and recommended optimizations for event-based tables. These optimizations also apply to the FIM events.

1. `--events_optimize=true` apply optimizations when `SELECT`ing from events-based tables, default enabled. 
2. `--events_expiry` the lifetime of buffered events in seconds, default 86000.
3. `--events_max` the maximum number of events to buffer, default 1000.

The goal of optimizations are to protect the running process and system from impacting performance. By default these are all enabled, which is good for configuration and performance, but may introduce inconsistencies on highly-stressed systems using process auditing.

Optimizations work best when `SELECT`ing often from event-based tables. Otherwise the events are in a buffered state. When an event-based table is selected within the daemon, the backing storage maintaining event data is cleared according to the `--event_expiry` lifetime. Setting this value to `1` will auto-clear events event select, reducing all impact of the buffer.
