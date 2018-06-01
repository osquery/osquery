The osquery shell and daemon use optional command line (CLI) flags to control
initialization, disable/enable features, and select plugins. These flags are powered by Google Flags and are somewhat complicated. Understanding how flags work in osquery will help with stability and greatly reduce issue debugging time.

Most flags apply to both tools, `osqueryi` and `osqueryd`. The shell contains a few more to help with printing and other helpful one-off modes of operation. Expect Linux / macOS / and Windows to include platform specific flags too. Most platform specific flags will control the OS API and library integrations used by osquery. Warning, this list is still not the 'complete set' of flags. Refer to the techniques below for obtaining ground truth and check other components of this Wiki.

Flags that do not control startup settings may be included as "options" within [configuration](../deployment/configuration.md). Essentially, any flag needed to help osquery determine and discover a configuration must be supplied via command line arguments. Google Flags enhances this to allow flags to be set within environment variables or via a "master" flag file.

To see a full list of flags for your osquery version use `--help` or select from the `osquery_flags` table:

```
$ osqueryi
osquery> SELECT * FROM osquery_flags;
```

To see the flags that have been updated by your configuration, a flag file, or by the shell try:

```
osquery> SELECT * FROM osquery_flags WHERE default_value <> value;
```

### Flagfile

A special flag, part of Google Flags, can be used to read additional flags from a line-delimited file. On macOS and Linux this `--flagfile` is the recommended way to add/remove the following CLI-only initialization flags.

`--flagfile /etc/osquery/osquery.flags`

Include line-delimited switches to be interpreted and used as CLI-flags:

```
--config_plugin=custom_plugin
--logger_plugin=custom_plugin
--distributed_plugin=custom_plugin
--watchlog_level=2
```

If no `--flagfile` is provided, osquery will try to find and use a "default" flagfile at `/etc/osquery/osquery.flags.default`. Both the shell and daemon will discover and use the defaults.

> NOTICE: Flags in a `flagfile` should not be wrapped in quotes, shell-macro/variable expansion is not applied!

### Configuration control flags

`--config_plugin=filesystem`

Config plugin name. The type of configuration retrieval, the default **filesystem** plugin reads a configuration JSON from disk.

Built-in options include: **filesystem**, **tls**

`--config_path=/etc/osquery/osquery.conf`

The **filesystem** config plugin's path to a JSON file.
On macOS the default path is **/var/osquery/osquery.conf**.
If you want to read from multiple configuration paths create a directory: **/etc/osquery/osquery.conf.d/**. All files within that optional directory will be read and merged in lexical order.

`--config_refresh=0`

An optional configuration refresh interval in seconds. By default a configuration is fetched only at osquery load. If the configuration should be auto-updated set a "refresh" time to a value in seconds greater than 0. If the configuration endpoint cannot be reached during runtime, the normal retry approach is applied (e.g., the **tls** config plugin will retry 3 times).

`--config_accelerated_refresh=300`

If a configuration refresh is used (`config_refresh > 0`) and the refresh attempt fails, the accelerated refresh will be used. This allows plugins like **tls** to fetch fresh data after having been offline for a while.

`--config_check=false`

Check the format of an osquery config and exit. Arbitrary config plugins may be used. osquery will return a non-0 exit if the parsing failed.

`--config_dump=false`

Request that the configuration JSON be printed to standard out before it is updated. In this case "updated" means applied to the active config. When osquery starts it performs an initial update from the config plugin. To quickly debug the content retrieved by custom config plugins use this in tandem with `--config_check`.

### Daemon control flags

`--force=false`

Force **osqueryd** to kill previously-running daemons. The daemon will check for an existing "pidfile". If found, and if it contains a pid of a process named "osqueryd", the process will be killed.

`--pidfile=/var/osquery/osqueryd.pidfile`

Path to the daemon pidfile mutex. The file is used to prevent multiple osqueryd processes starting.

`--disable_watchdog=false`

Disable userland watchdog process. **osqueryd** uses a watchdog process to monitor the memory and CPU utilization of threads executing the query schedule. If any performance limit is violated the "worker" process will be restarted.

`--watchdog_level=0`

Performance limit level (0=normal, 1=restrictive, -1=disabled). The watchdog process uses a "level" to configure performance limits.

The level limits are as follows:
Memory: default 200M, restrictive 100M
CPU: default 25% (for 9 seconds), restrictive 18% (for 9 seconds)

The normal level allows for 10 restarts if the limits are violated. The restrictive allows for only 4, then the service will be disabled. For both there is a linear backoff of 5 seconds, doubling each retry.

It is better to set the level to disabled `-1` compared to disabling the watchdog outright as the worker/watcher concept is used for extensions autoloading too. The watchdog "profiles" can be overridden for Memory and CPU Utilization.

`--watchdog_memory_limit=0`

If this value is >0 then the watchdog level (`--watchdog_level`) for maximum memory is overridden. Use this if you would like to allow the `osqueryd` process to allocate more than 200M, but somewhere less than 1G. This memory limit is expressed as a value representing MB.

`--watchdog_utilization_limit=0`

If this value is >0 then the watchdog level (`--watchdog_level`) for maximum sustained CPU utilization is overridden. Use this if you would like to allow the `osqueryd` process to use more than 30% of a thread for more than 9 seconds of wall time. The length of sustained utilization is not independently configurable.

This value is a maximum number of CPU cycles counted as the `processes` table's `user_time` and `system_time`. The default is 90, meaning less 90 seconds of cpu time per 3 seconds of wall time is allowed.

`--watchdog_delay=60`

A delay in seconds before the watchdog process starts enforcing memory and CPU utilization limits. The default value `60s` allows the daemon to perform resource intense actions, such as forwarding logs, at startup.

`--enable_extensions_watchdog=false`

By default the watchdog monitors extensions for improper shutdown, but NOT for performance and utilization issues. Enable this flag if you would like extensions to use the same CPU and memory limits as the osquery worker. This means that your extensions or third-party extensions may be asked to stop and restart during execution.

`--utc=true`

Attempt to convert all UNIX calendar times to UTC.

`--table_delay=0`

Add a microsecond delay between multiple table calls (when a table is used in a JOIN). A `200` microsecond delay will trade about 20% additional time for a reduced 5% CPU utilization.

`--hash_cache_max=500`

The `hash` table implements a cache that is invalidated when file path inodes are changed. Eviction occurs in chunks if the max-size is reached. This max should remain relatively low since it will persist in the daemon's resident memory.

`--hash_delay=20`

Add a millisecond delay between multiple `hash` attempts (aka when scanning a directory). This adds about 50% additional wall-time for 150 files. This reduces the instantaneous resource need from hashing new files.

`--disable_hash_cache=false`

Set this to true if you would like to disable file hash caching and always regenerate the file hashes every request. The default osquery configuration may report hashes incorrectly if things are editing filesystems outside of the OS's control.

**Windows Only**

Windows builds include a `--install` and `--uninstall` that will create a Windows service using the `osqueryd.exe` binary and preserve an optional `--flagfile` if provided.

### Backing storage control flags

`--database_path=/var/osquery/osquery.db`

If using a disk-based backing store, specify a path. osquery will keep state using a "backing store" using RocksDB by default. This state holds event information such that it may be queried later according to a schedule. It holds the results of the most recent query for each query within the schedule. This last-queried result allows query-differential logging.

`--database_dump=false`

Helpful for debugging database problems. This will print a line for each key in the backing store. Note: There could be MBs worth of data in the backing store.

### Extensions control flags

`--disable_extensions=false`

Disable extension API. See the [SDK development](../development/osquery-sdk.md) page for more information on osquery extensions, and the [deployment](../deployment/extensions.md) page for how to use extensions.

`--extensions_socket=/var/osquery/osquery.em`

Path to the extensions UNIX domain socket.
[Extensions](../deployment/extensions.md) use a UNIX domain socket for communication. It is very uncommon to change the location of the file. The osquery shell may use extensions, but the socket location is relative to the user invoking the shell and does not support concurrent shells.

`--extensions_autoload=/etc/osquery/extensions.load`

Optional path to a list of autoloaded and managed extensions.
If using an extension to provide a proprietary config or logger plugin the extension process can be started by the daemon. Include line-delimited paths to extension executables. See the extensions [deployment](../deployment/extensions.md) page for more details on extension autoloading.

`--extensions_timeout=3`

Seconds to wait for autoloaded extensions to register.
osqueryd may depend on a config plugin from an extension. If the requested config plugin name is not registered within the timeout the daemon will exit with a failure.

`--extensions_interval=3`

Seconds delay between extension connectivity checks.
Extensions are loaded as processes. They are expected to start a thrift service thread. The osqueryd process will continue to check this API. If an extension process is incorrectly stopped, osqueryd will detect the connectivity failure and unregister the extension.

`--extensions_require=custom1,custom1`

Optional comma-delimited set of extension names to require before **osqueryi** or **osqueryd** will start. The tool will fail if the extension has not started according to the interval and timeout.

### Remote settings flags (optional)

When using non-default [remote](../deployment/remote.md) plugins such as the **tls** config, logger and distributed plugins, there are process-wide settings applied to every plugin.

`--tls_hostname=`

When using **tls**-based config or logger plugins, a single TLS host URI is used. Using separate hosts for configuration and logging is not supported among the **tls**-based plugin suite. Provide a host name and optional port, e.g.: `facebook.com` or `facebook.com:443`.

`--tls_session_reuse=true`

Reuse TLS session sockets.

`--tls_session_timeout=3600`

Once a socket is created the life time is governed by this flag. If this value is set as zero then transport never times out unless the remote end closes the connection or an error occurs.

`--tls_client_cert=`

See the **tls**/[remote](../deployment/remote.md) plugin documentation. Optionally provide a path to a PEM-formatted client TLS certificate.

`--tls_client_key=`

See the **tls**/[remote](../deployment/remote.md) plugin documentation. Optionally provide a path to a decrypted/password-less PEM-formatted client TLS private key.

`--tls_server_certs=`

See the **tls**/[remote](../deployment/remote.md) plugin documentation. Optionally provide a path to a PEM-formatted server or authority certificate bundle. This path will be used as either an explicit set of accepted certificates or an OpenSSL-verify path directory of well-formed filename certificates.

`--disable_enrollment=false`

See the **tls**/[remote](../deployment/remote.md) plugin documentation. Remote plugins use an enrollment process to enable possible server-side implemented authentication and identification/authorization. Config and logger plugins implicitly require enrollment features. It is not recommended to disable enrollment and this option may be removed in the future.

`--enroll_secret_path=`

See the **tls**/[remote](../deployment/remote.md) plugin documentation. A very simple authentication/enrollment involves posting a deployment or staged shared secret. This secret should be protected on the host, but potentially shared among an enterprise or fleet. Provide a path for the osquery process to read and use during enrollment phases.

`--config_tls_endpoint=`

The **tls** endpoint path, e.g.: **/api/v1/config** when using the **tls** config plugin. See the other **tls_** related CLI flags.

`--config_tls_max_attempts=3`

The total number of attempts that will be made to the remote config server if a request fails.

`--logger_tls_endpoint=`

The **tls** endpoint path, e.g.: **/api/v1/logger** when using the **tls** logger plugin. See the other **tls_** related CLI flags.

`--enrollment_tls_endpoint=`

See the **tls**/[remote](../deployment/remote.md) plugin documentation. An enrollment process will be used to allow server-side implemented authentication and identification/authorization. You must provide an endpoint relative to the `--tls_hostname` URI.

`--logger_tls_period=3`

See the **tls**/[remote](../deployment/remote.md) plugin documentation. This is a number of seconds before checking for buffered logs. Results are sent to the TLS endpoint in intervals, not on demand (unless the period=0).

`--logger_tls_compress=false`

Optionally enable GZIP compression for request bodies when sending. This is optional, and disabled by default, as the deployment must explicitly know that the logging endpoint supports GZIP for content encoding.

`--logger_tls_max=1048576`

It is common for TLS/HTTPS servers to enforce a maximum request body size. The default behavior in osquery is to enforce each log line be under 1M bytes. This means each result line from a query's results cannot exceed 1M, this is very unlikely. Each log attempt will try to forward up to 1024 lines. If your service is limited request bodies, configure the client to limit the log line size.

Use this only in emergency situations as size violations are dropped. It is extremely uncommon for this to occur, as the `--value_max` for each column would need to be drastically larger, or the offending table would have to implement several hundred columns.

`--distributed_tls_read_endpoint=`

The URI path which will be used, in conjunction with `--tls_hostname`, to create the remote URI for retrieving distributed queries when using the **tls** distributed plugin.

`--distributed_tls_write_endpoint=`

The URI path which will be used, in conjunction with `--tls_hostname`, to create the remote URI for submitting the results of distributed queries when using the **tls** distributed plugin.

`--distributed_tls_max_attempts=3`

The total number of attempts that will be made to the remote distributed query server if a request fails when using the **tls** distributed plugin.

### Daemon runtime control flags

`--schedule_splay_percent=10`

Percent to splay config times.
The query schedule often includes several queries with the same interval.
It is often not the intention of the schedule author to run these queries together at that interval. But rather, each query should run at about the interval. A default schedule splay of 10% is applied to each query when the configuration is loaded.

`--pack_refresh_interval=3600`

Query Packs may optionally include one or more discovery queries, which allow
you to use osquery queries to manage which packs should be loaded at runtime.
Osquery will natively re-run the discovery queries from time to time, to make
sure that all of the correct packs are executing. This flag allows you to
specify that interval.

`--pack_delimiter=_`

Control the delimiter between pack name and pack query names. When queries are added to the daemon's schedule they inherit the name of the pack. A query named `info` within the `general_info` pack will become `pack_general_info_info`. Changing the delimiter to "/" turned the scheduled name into: `pack/general_info/info`.

`--disable_caching=false`

"Caching" refers to short cutting the table implementation and returning the same results from the previous query against the table. This is not related to differential results from scheduled queries, but does affect the performance of the schedule. Results are cached when different scheduled queries in a schedule use the same table, without providing query constraints. Caching should NOT affect data freshness since the cache life is determined as the minimum interval of all queries against a table.

`--schedule_default_interval=3600`

Optionally set the default interval value. This is used if you schedule a query
which does not define an interval.

`--schedule_timeout=0`

Limit the schedule, 0 for no limit. Optionally limit the `osqueryd`'s life by adding a schedule limit in seconds. This should only be used for testing.

`--disable_tables=table_name1,table_name2`

Comma-delimited list of table names to be disabled. This allows osquery to be launched without certain tables.

`--read_max=52428800` (50MB)

Maximum file read size. The daemon or shell will first 'stat' each file before reading. If the reported size is greater than `read_max` a "file too large" error will be returned.

### Events control flags

`--disable_events=false`

Disable osquery Operating System [eventing publish subscribe](../development/pubsub-framework.md) APIs. This will implicitly disable several tables that report based on logged events.

`--events_expiry=3600`

Timeout to expire [eventing publish subscribe](../development/pubsub-framework.md) results from the backing-store. This expiration is only applied when results are queried. For example, if `--events_expiry=1` then events will only practically exist for a single select from the subscriber. If no select occurs then events will be saved in the backing store indefinitely.

`--events_optimize=true`

Since event rows are only "added" it does not make sense to emit "removed" results. An optimization can occur within the osquery daemon's query schedule. Every time the select query runs on a subscriber the current time is saved. Subsequent selects will use the previously saved time as the lower bound. This optimization is removed if any constraints on the "time" column are included.

`--events_max=50000`

Maximum number of events to buffer in the backing store while waiting for a query to 'drain' or trigger an expiration. If the expiration (`events_expiry`) is set to 1 hour, this max value indicates that only 50000 events will be stored before dropping each hour. In this case the limiting time is almost always the scheduled query. If a scheduled query that select from events-based tables occurs sooner than the expiration time that interval becomes the limit.

**Windows Only**

`--windows_event_channels=System,Application,Setup,Security`

List of Windows event log channels to subscribe to. By default the Windows event log publisher will subscribe to some of the more common major event log channels. However you can subscribe to additional channels using the `Log Name` field value in the Windows event viewer. Note the lack of quotes around the channel names. For example, to subscribe to Windows Powershell script block logging one would first enable the feature and then subscribe to the channel with `--windows_event_channels=Microsoft-Windows-PowerShell/Operational`

**Linux Only**

`--hardware_disabled_types=partition`

This is a comma-separated list of UDEV types to drop. On machines with flash-backed storage it is likely you'll encounter lots of noise from `disk` and `partition` types.

### Logging/results flags

`--logger_plugin=filesystem`

Logger plugin name. The default logger is **filesystem**. This writes the various log types as JSON to specific file paths.

Multiple logger plugins may be used simultaneously, effectively copying logs to each interface. Separate plugin names with a comma when specifying the configuration (`--logger_plugin=filesystem,syslog`).

Built-in options include: **filesystem**, **tls**, **syslog**, and several Amazon/AWS options.

`--disable_logging=false`

Disable ERROR/WARNING/INFO (called status logs) and query result [logging](../deployment/logging.md).

`--logger_event_type=true`

Log scheduled results as events.

`--logger_snapshot_event_type=false`

Log scheduled snapshot results as events, similar to differential results. If this is set to `true` then each row from a snapshot query will be logged individually.

`--logger_min_status=0`

The minimum level for status log recording. Use the following values: `INFO = 0, WARNING = 1, ERROR = 2`. To disable all status messages use 3+. When using `--verbose` this value is ignored.

`--logger_min_stderr=0`

The minimum level for status logs written to stderr. Use the following values: `INFO = 0, WARNING = 1, ERROR = 2`. To disable all status messages use 3+. It does NOT limit or control the types sent to the logger plugin. When using `--verbose` this value is ignored.

`--logger_stderr=true`

The default behavior is to also write status logs to stderr. Set this flag to false to disable writing (copying) status logs to stderr. In this case `--verbose` is respected.

`--logger_secondary_status_only=false`

This is a rarely used logger plugin option. When enabled, the "secondary" logger plugins will only receive status logs. For an example if your `-logger_plugin=tls,firehose,syslog` then status logs would be sent to all 3 plugins, and query results will only be sent to `tls`.

`--host_identifier=hostname`

Field used to identify the host running osquery: **hostname**, **uuid**, **ephemeral**, **instance**, **specified**.

DHCP may assign variable hostnames, if this is the case, you may need a consistent logging label. Four options are available to you:

- `uuid` uses the platform (DMTF) host UUID, fetched at process start.
- `instance` uses an instance-unique UUID generated at process start, persisted in the backing store.
- `ephemeral` uses an instance-unique UUID generated at process start, not persisted.
- `specified` uses an ID provided by the `--specified_identifier` flag.

`--specified_identifier=this.is.the.identifier`

If `--host_identifier=specified` is set, use this value as the host identifier.

`--verbose=false`

Enable verbose informational messages.

`--logger_path=/var/log/osquery/`

Directory path for ERROR/WARN/INFO and results logging.

`--logger_mode=420`

File mode for output log files (provided as a decimal string).  Note that this
affects both the query result log and the status logs. **Warning**: If run as root, log files may contain sensitive information!

`--value_max=512`

Maximum returned row value size.

`--logger_syslog_facility`

Set the syslog facility (number) 0-23 for the results log. When using the **syslog** logger plugin the default facility is 19 at the `LOG_INFO` level, which does not log to `/var/log/system`.

`--logger_syslog_prepend_cee`

Prepend a `@cee:` cookie to JSON-formatted messages sent to the **syslog** logger plugin. Several syslog parsers use this cookie to indicate that the message payload is parseable JSON. The default value is false.

`--logger_kafka_brokers`

A comma delimited list of Kafka brokers to connect to.  Format can be `protocol://host:port`, `host:port` or just `host` with the port number falling back to the default value of `9092`.  `protocol` can be `plaintext` (default) or `ssl`.  When protocol is `ssl`, `--tls_server_certs` value is used as certificate trust store.  Optionally `--tls_client_cert` and `--tls_client_key` can be provided for TLS client authentication with Kafka brokers.

`--logger_kafka_topic`

The Kafka topic to publish logs to.  When using multiple topics this configuration becomes the base topic that unconfigured queries fall back to.  Please see the Kafka section of the [logging wiki](../deployment/logging.md) for more details.

`--logger_kafka_acks`

The number of acknowledgments the Kafka leader has to receive before a publish is considered successful.  Valid options are (0, 1, "all").

`--logger_kafka_compression`

Compression codec to use for compressing message sets.  Valid options are ("none", "gzip").  Default is "none".

### Distributed query service flags

`--distributed_plugin=tls`

Distributed plugin name. The default distributed plugin is not set. You must set `--disable_distributed=false --distributed_plugin=tls` (or whatever plugin you'd rather use instead of TLS) to enable the distributed feature.

`--disable_distributed=true`

Disable distributed queries functionality. By default, this is set to `true` (the distributed feature is disabled). Set this to `false` to enable distributed queries.

`--distributed_interval=60`

In seconds, the amount of time that osqueryd will wait between periodically checking in with a distributed query server to see if there are any queries to execute.

### Syslog consumption

There is a `syslog` virtual table that uses Events and a **rsyslog** configuration to capture results *from* syslog. Please see the [Syslog Consumption](../deployment/syslog.md) deployment page for more information.

`--enable_syslog=false`

Turn on the syslog ingestion event publisher. This is an 'explicit'-enable because it requires external configuration of **rsyslog**.

`--syslog_pipe_path=/var/osquery/syslog_pipe`

Path to the named pipe used for forwarding **rsyslog** events.

`--syslog_rate_limit=100`

Maximum number of logs to ingest per run (~200ms between runs). Use this as a fail-safe to prevent osquery from becoming overloaded when syslog is spammed.

### Augeas flags

`--augeas_lenses=/usr/share/osquery/lenses`

Augeas lenses are bundled with osquery distributions. On Linux they are installed in /usr/share/osquery/lenses. On macOS lenses are installed in /private/var/osquery/lenses directory. Specify the path to the directory containing custom or different version lenses files.

### Docker flags

`--docker_socket=/var/run/docker.sock`

Docker information for containers, networks, volumes, images etc is available in different tables. osquery uses docker's UNIX domain socket to invoke docker API calls. Provide the path to docker's domain socket file. User running osqueryd / osqueryi should have permission to read the socket file.

### Shell-only flags

Most of the shell flags are self-explanatory and are adapted from the SQLite shell. Refer to the shell's ".help" command for details and explanations.

There are several flags that control the shell's output format: `--json`, `--list`, `--line`, `--csv`. For all of the output types there is `--nullvalue` and `--separator` that can be used appropriately.

`--planner=false`

When prototyping new queries the planner enables verbose decisions made by the SQLite virtual table API. This is customized by osquery code so it is very helpful to learn what predicate constraints are selected and what full table scans are required for JOINs and nested queries.

`--header=true`

Set this value to `false` to disable column name (header) output. If using the shell in an automation or script the header line in `line` or `csv` mode may not be needed.
