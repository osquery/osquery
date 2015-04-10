The osquery shell and daemon use optional command line (CLI) flags to control
initialization, disable/enable features, and select plugins.

Most of these flag-based parameters apply to both tools and those that do not
control startup settings may be included as "options" to the daemon within its [configuration](../deployment/configuration).

## CLI-only (initialization) flags

`--config_plugin="filesystem"`

Config plugin name

The plugin/type of configuration retrieval, the default "filesystem" plugin reads a configuration JSON from disk.

`--config_path="/etc/osquery/osquery.conf`

(filesystem) config plugin path to JSON config file

The filesystem config plugin's path to a JSON file.
On OS X the default path is "/var/osquery/osquery.conf".
If you want to read from multiple configuration paths create a directory: "/etc/osquery/osquery.conf.d".
All files within that optional directory will be read and merged in lexical order.

`--config_check=false`

Check the format of an osquery config and exit

`--force=false`

Force osqueryd to kill previously-running daemons

`--pidfile=/var/osquery/osqueryd.pidfile`

Path to the daemon pidfile mutex

Prevent multiple osqueryd daemons from running simultaneously using a pidfile.
osqueryd will check for this file to exists, if it does it will read a pid
and check if that process is an existing osqueryd, if so, subsequent execution
will stop.

`--disable_watchdog=false`

Disable userland watchdog process

osqueryd uses a watchdog process to monitor the memory and CPU utilization
of threads executing the query schedule. If any performance limit is violated
the "worker" process and schedule threads will be restarted.

`--watchdog_level=1`

Performance limit level (0=loose, 1=normal, 2=restrictive, 3=debug)

The default watchdog process uses a "level" to configure performance limits.
The higher the level the more strict the limits become.

`--schedule_timeout=0`

Limit the schedule, 0 for no limit

Optionally limit the osqueryd's life by adding a schedule limit in seconds.
This should only be used for testing.

`--disable_extensions=false`

Disable extension API

`--extensions_autoload=/etc/osquery/extensions.load`

Optional path to a list of autoloaded & managed extensions

`--extensions_interval=3`

Seconds delay between connectivity checks

`--extensions_socket=/var/osquery/osquery.em`

Path to the extensions UNIX domain socket

Extensions use a UNIX domain socket for communication.
It is very uncommon to change the local of the file.
The osquery shell may use extensions, but the socket location is relative to the
user invoking the shell and does not support concurrent shells.

`--extensions_timeout=3`

Seconds to wait for autoloaded extensions

`--modules_autoload=/etc/osquery/modules.load`

Optional path to a list of autoloaded registry modules

## Runtime flags

`--schedule_splay_percent=10`

Percent to splay config times

The query schedule often includes several queries with the same interval.
It is often not the intention of the schedule author to run these queries together
at that interval. But rather, each query should run at about the interval.
A default schedule splay of 10% is applied to each query when the configuration is loaded.

`--database_in_memory=false`

Keep osquery backing-store in memory

Optionally keep osquery-state in memory.
This has a number of performance implications and is not recommended.
For the default backing-store, RocksDB, this option is not supported.

`--database_path=/var/osquery/osquery.db`

If using a disk-based backing store, specify a path

osquery will keep state using a "backing store" using RocksDB by default.
This state holds event information such that it may be queried later according
to a schedule. It holds the results of the most recent query for each query within
the schedule. This last-queried result allows query-differential logging.

`--worker_threads=4`

Number of work dispatch threads

`--host_identifier=hostname`

Field used to identify the host running osquery (hostname, uuid)

Select either "hostname" or "uuid" for the host identifier.
DHCP may assign variable hostnames, if this is the case, select UUID for a
consistant logging label.

`--distributed_get_queries_retries=3`

Times to retry retrieving distributed queries

`--distributed_write_results_retries=3`

Times to retry writing distributed query results

`--disable_events=false`

Disable osquery events pubsub

`--events_expiry=86000`

Timeout to expire event pubsub results

`--disable_logging=false`

Disable ERROR/INFO logging

`--log_result_events=true`

Log scheduled results as events

`--logger_plugin=filesystem`

Logger plugin name

`--verbose=false`

Enable verbose informational messages

`--logger_path=/var/log/osquery/`

Directory path for ERROR/WARN/INFO and results logging

`--value_max=512`

Maximum returned row value size

## Shell-only flags

Most of the shell flags are self-explainitory and are adapted from the SQLite shell.
Refer the shell's ".help" command for details and explainations.

`--bail=false`

stop after hitting an error

`--batch=false`

force batch I/O

`--column=false`

set output mode to 'column'

`--csv=false`

set output mode to 'csv'

`--echo=false`

print commands before execution

`--explain=false`

Explain each query by default

`--header=on`

turn headers on or off

`--html=false`

set output mode to HTML

`--interactive=false`

force interactive I/O

`--json=false`

set output mode to 'json'

`--line=false`

set output mode to 'line'

`--list=false`

set output mode to 'list'

`--nullvalue=''`

set text string for NULL values. Default ''

`--separator='|'`

set output field separator. Default: '|'

`--stats=false`

print memory stats before each finalize
