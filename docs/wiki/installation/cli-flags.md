The osquery shell and daemon use optional command line (CLI) flags to control
initialization, disable/enable features, and select plugins.

Most of these flag-based parameters apply to both tools. Flags that do not
control startup settings may be included as "options" to the daemon within its [configuration](../deployment/configuration).

## CLI-only (initialization) flags

`--config_plugin="filesystem"`

Config plugin name. The type of configuration retrieval, the default "filesystem" plugin reads a configuration JSON from disk.

`--config_path="/etc/osquery/osquery.conf"`

The "filesystem" config plugin's path to a JSON file.
On OS X the default path is "/var/osquery/osquery.conf".
If you want to read from multiple configuration paths create a directory: "/etc/osquery/osquery.conf.d/".
All files within that optional directory will be read and merged in lexical order.

`--config_check=false`

Check the format of an osquery config and exit. Arbitrary config plugins may be used. osquery will return a non-0 exit if the parsing failed.

`--force=false`

Force osqueryd to kill previously-running daemons. The daemon will check for an existing "pidfile". If found, and if it contains a pid of a process named "osqueryd", the process will be killed.

`--pidfile=/var/osquery/osqueryd.pidfile`

Path to the daemon pidfile mutex.
The file is used to prevent multiple osqueryd processes starting.

`--disable_watchdog=false`

Disable userland watchdog process.
osqueryd uses a watchdog process to monitor the memory and CPU utilization
of threads executing the query schedule. If any performance limit is violated
the "worker" process will be restarted.

`--watchdog_level=1`

Performance limit level (0=loose, 1=normal, 2=restrictive, 3=debug). The default watchdog process uses a "level" to configure performance limits.
The higher the level the more strict the limits become.

`--schedule_timeout=0`

Limit the schedule, 0 for no limit. Optionally limit the osqueryd's life by adding a schedule limit in seconds.
This should only be used for testing.

`--disable_extensions=false`

Disable extension API.

`--extensions_socket=/var/osquery/osquery.em`

Path to the extensions UNIX domain socket.
Extensions use a UNIX domain socket for communication.
It is very uncommon to change the local of the file.
The osquery shell may use extensions, but the socket location is relative to the
user invoking the shell and does not support concurrent shells.

`--extensions_autoload=/etc/osquery/extensions.load`

Optional path to a list of autoloaded and managed extensions.
If using an extension to provide a proprietary config or logger plugin the extension process can be started by the daemon. Include line-delimited paths to extension executables.

`--extensions_timeout=3`

Seconds to wait for autoloaded extensions to register.
osqueryd may depend on a config plugin from an extension. If the requested config plugin name is not registered within the timeout the daemon will exit with a failure.

`--extensions_interval=3`

Seconds delay between extension connectivity checks.
Extensions are loaded as processes. They are expected to start a thrift service thread. The osqueryd process will continue to check this API. If an extension process is incorrectly stopped, osqueryd will detect the connectivity failure and unregister the extension.


`--modules_autoload=/etc/osquery/modules.load`

Optional path to a list of autoloaded registry modules. Modules are similar to extensions but are loaded as shared libraries. They are less flexible and should be built using the same GCC runtime and developer dependency library versions as osqueryd.

## Runtime flags

`--schedule_splay_percent=10`

Percent to splay config times.
The query schedule often includes several queries with the same interval.
It is often not the intention of the schedule author to run these queries together
at that interval. But rather, each query should run at about the interval.
A default schedule splay of 10% is applied to each query when the configuration is loaded.

`--database_in_memory=false`

Keep osquery backing-store in memory.
This has a number of performance implications and is not recommended.
For the default backing-store, RocksDB, this option is not supported.

`--database_path=/var/osquery/osquery.db`

If using a disk-based backing store, specify a path.
osquery will keep state using a "backing store" using RocksDB by default.
This state holds event information such that it may be queried later according
to a schedule. It holds the results of the most recent query for each query within
the schedule. This last-queried result allows query-differential logging.

`--worker_threads=4`

Number of work dispatch threads.

`--host_identifier=hostname`

Field used to identify the host running osquery (hostname, uuid)

Select either "hostname" or "uuid" for the host identifier.
DHCP may assign variable hostnames, if this is the case, select UUID for a
consistant logging label.

`--distributed_get_queries_retries=3`

Times to retry retrieving distributed queries.

`--distributed_write_results_retries=3`

Times to retry writing distributed query results.

`--disable_events=false`

Disable osquery events pubsub.

`--disable_tables=table_name1,table_name2`

Comma-delimited list of table names to be disabled.
This allows osquery to be launched without certain tables.

`--events_expiry=86000`

Timeout to expire event pubsub results.

`--disable_logging=false`

Disable ERROR/INFO logging.

`--log_result_events=true`

Log scheduled results as events.

`--logger_plugin=filesystem`

Logger plugin name.

`--verbose=false`

Enable verbose informational messages.

`--logger_path=/var/log/osquery/`

Directory path for ERROR/WARN/INFO and results logging.

`--value_max=512`

Maximum returned row value size.

## Shell-only flags

Most of the shell flags are self-explainitory and are adapted from the SQLite shell. Refer the shell's ".help" command for details and explainations.

We have added a `--json` switch to output rows as a JSON list.
