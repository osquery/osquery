Here are some debugging tips and tricks related to the daemon and shell from a deployment and usage perspective. Please see the development documentation in the next section for debugging code changes.

Almost every situation requiring debugging should ultimately be solved with bug fixes or better documentation. In these cases the documentation usually surfaces in the form of verbose messages in the tools.

Please feel encouraged to add additional messages in the code, or create Github issues documenting your experience and suggestions for documentation or code improvements.

### Running the shell or daemon in verbose mode

This is pretty simple! Just append `--verbose` as a switch.

```
$ osqueryi --verbose
I0119 16:38:03.113173 1965629440 init.cpp:278] osquery initialized [version=1.6.3]
I0119 16:38:03.113536 1965629440 extensions.cpp:177] Could not autoload modules: Failed reading: /etc/osquery/modules.load
I0119 16:38:03.132020 1064960 interface.cpp:246] Extension manager service starting: /Users/reed/.osquery/shell.em
I0119 16:38:03.132203 1965629440 db_handle.cpp:165] Opening RocksDB handle: /Users/reed/.osquery/shell.db
I0119 16:38:03.141836 1965629440 events.cpp:555] Event publisher failed setup: kernel: Cannot access /dev/osquery
W0119 16:38:03.142004 1965629440 events.cpp:757] Error registering subscriber: process_file_events: No kernel event publisher
I0119 16:38:03.143363 5844992 events.cpp:498] Starting event publisher run loop: diskarbitration
I0119 16:38:03.143702 6381568 events.cpp:498] Starting event publisher run loop: fsevents
I0119 16:38:03.145011 6918144 events.cpp:498] Starting event publisher run loop: iokit
I0119 16:38:03.149258 7454720 events.cpp:498] Starting event publisher run loop: scnetwork
osquery - being built, with love, at Facebook
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Using a virtual database. Need help, type '.help'
osquery>
```

To see the daemon's verbose messages you'll need to run it in the foreground, see the next section. Be aware that verbose messages are treated like others and sent to your downstream logger plugin. If you are collecting these logs, the verbose messages will be collected too!

### Running the daemon in the foreground

The daemon has some restrictions that make verbose debugging difficult, let's walk through how to run it in the foreground.

```
$ osqueryd --pidfile /tmp/osquery.pid --database_path /tmp/osquery.db
```

The `pidfile` and `database_path` must be overridden as the defaults are not writable/readable by a non-privileged user. Now we can append `--verbose`:

```
$ osqueryd --pidfile /tmp/osquery.pid --database_path /tmp/osquery.db --verbose
I0119 16:45:17.785065 1965629440 init.cpp:278] osquery initialized [version=1.6.4-13]
I0119 16:45:17.816946 1965629440 system.cpp:183] Found stale process for osqueryd (22391) removing pidfile
I0119 16:45:17.818084 1965629440 system.cpp:218] Writing osqueryd pid (22406) to /tmp/osquery.pid
I0119 16:45:17.820576 1965629440 extensions.cpp:170] Could not autoload extensions: Failed reading: /etc/osquery/extensions.load
I0119 16:45:17.823276 528384 watcher.cpp:371] osqueryd watcher (22406) executing worker (22407)
I0119 16:45:17.840364 1965629440 init.cpp:276] osquery worker initialized [watcher=22406]
I0119 16:45:17.841305 1965629440 extensions.cpp:177] Could not autoload modules: Failed reading: /etc/osquery/modules.load
I0119 16:45:17.847304 1965629440 db_handle.cpp:165] Opening RocksDB handle: /tmp/osquery.db
Could not create log file: Permission denied
COULD NOT CREATE LOGFILE '20160119'!
I0119 16:45:17.857830 1965629440 events.cpp:555] Event publisher failed setup: kernel: Cannot access /dev/osquery
W0119 16:45:17.857889 1965629440 events.cpp:757] Error registering subscriber: process_file_events: No kernel event publisher
I0119 16:45:17.857990 1965629440 daemon.cpp:39] Not starting the distributed query service: Distributed query service not enabled.
I0119 16:45:17.858032 3211264 events.cpp:498] Starting event publisher run loop: diskarbitration
I0119 16:45:17.858038 3747840 events.cpp:498] Starting event publisher run loop: fsevents
I0119 16:45:17.858070 4284416 events.cpp:498] Starting event publisher run loop: iokit
I0119 16:45:17.858481 4820992 events.cpp:498] Starting event publisher run loop: scnetwork
```

There are errors from Glog about logging permissions, to silence them make a directory and override `--logger_path`. Also note the the daemon wants you to execute it as the user who owns the binary if you attempt to run as a superuser. It also resists running in a tmpfs or sticky-bit directory.

If you are using a `--flagfile` to define additional command line switches then it should be readable by your user. In cases where the Remote API is used, an enroll secret or TLS client private key is needed. If these are read-restricted to the superuser you may need to also debug as the superuser.

### Checking the config sanity

The daemon will not start with an invalid configuration. And no configuration is provided by default. See the [configuration](../deployment/configuration.md) guide for details on how to move the example config to an active config.

To check your configuration with the shell (or daemon):

```
$ osqueryi --config_path ./build/testing/invalid_osquery.conf --config_check || echo 'config has an error'
Error reading config: Error parsing the config JSON
config has an error
```

This works for all the configuration plugins.

You can print/dump the config using `--config_dump` to be double-extra sure:

```
osqueryi --config_path ./build/testing/invalid_osquery.conf --config_dump
{"./build/testing/osquery.conf": /* I PUT THIS JSON ERROR HERE, NOOOOO! */
{
 "packs": {}
}
```

In this example I've add a C-style comment which [used](https://github.com/facebook/osquery/issues/1689) to be allowed in boost 1.58, but was deprecated and removed in 1.59. To be future-proof, stick to the JSON specification and do not include comments.

### Scheduled query failures and the watchdog

The osquery watchdog is only used in the daemon. It is enabled by default and can be disabled with `--disable_watchdog=true`. The watchdog enforces limits on a forked 'worker' process to protect systems from CPU expensive and memory-intensive queries. If the watchdog observes limit violations it will emit errors similar to:

```
Scheduled query may have failed: pack_threat_detectors_launch_daemons
```

This line is created when a worker starts and finds a 'dirty bit' toggled for the currently-executing-query. If a daemon is stopped abruptly and a query does not finish, a similar line may be emitted spuriously.

Lines that indicate the watchdog has taken action include either of the following:

```
osqueryd worker (92234) system performance limits exceeded
osqueryd worker (8368) memory limits exceeded: 99573760
```

The pid of the offending worker is included in parenthesis.

If the worker finds itself in a re-occurring error state or the watchdog continues to stop the worker, additional lines like the following are created:

```
osqueryd worker respawning too quickly: 1 times
```

The watchdog implements an exponential backoff when respawning workers and the associated 'dirty' query is blacklisted from running for 24 hours.

### Checking the database sanity

The osquery backing store is almost always RocksDB. This is built-in to osquery when using [our packages](https://osquery.io/downloads). Most errors with RocksDB are caused by read and write permissions on the `--database_path` and spurious processes wanting to lock access to that directory.

The database path can only be used by a **single** daemon, concurrency is implemented at the API level, not the process level.

```
$ ps aux | grep osquery
# pgrep osquery
```

If osquery daemons or shells are using the database path wanted by a daemon you're attempting to start, it will fail and exit non-0. There is one unfortunate caveat introduced by the lock, consider the following flow:

```
$ sudo osqueryctl start
$ sudo osqueryctl config-check
E0118 17:10:09.520731 1913696256 init.cpp:421] [Ref #1629] osqueryd initialize failed: Could not open RocksDB
$ sudo osqueryctl status
com.facebook.osqueryd is running. pid: 81943
$ sudo osqueryctl stop
$ sudo osqueryctl config-check || echo 'config has an error'
```

The first `config-check` fails because it attempts to verify the sanity of the RocksDB directory while a daemon is running. The second attempt succeeds and should be the actual indicator!

### Missing event subscribers

If you see:

```
Error registering subscriber: process_file_events: No kernel event publisher
```

This is an informational message with mis-categorized severity. The message indicates that a requested companion kernel extension does not exist and the associated `process_file_events` subscriber on OS X cannot start. It is safe to ignore.
