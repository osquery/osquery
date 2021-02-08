# Using osqueryi

`osqueryi` is the osquery interactive query console/shell. In this mode, it is completely standalone, does not communicate with a daemon, and does not need to run as an administrator (although some tables may return fewer results when running as non-administrator). Use the osquery shell to prototype queries and explore the current state of your operating system.

## Executing SQL queries

`osqueryi` lets you run meta-commands and query osquery tables. See the [schema API](https://osquery.io/schema/) for a complete list of tables, types, and column descriptions. For SQL syntax help, see [SQL as understood by SQLite](https://www.sqlite.org/lang.html).

***Note***: the `osqueryd` binary, when run as `osqueryd -S`, operates as `osqueryi`. It will also operate in the interactive mode if the executable is renamed as `osqueryi`.

Here is an example query:

```
$ osqueryi
osquery> SELECT DISTINCT
    ...>   process.name,
    ...>   listening.port,
    ...>   process.pid
    ...> FROM processes AS process
    ...> JOIN listening_ports AS listening
    ...> ON process.pid = listening.pid
    ...> WHERE listening.address = '0.0.0.0';

+----------+-------+-------+
| name     | port  | pid   |
+----------+-------+-------+
| Spotify  | 57621 | 18666 |
| ARDAgent | 3283  | 482   |
+----------+-------+-------+
osquery>
```

The shell accepts a single positional argument and one of the several output modes. If you want to output JSON or CSV values, try:

```
$ osqueryi --json "SELECT * FROM routes WHERE destination = '::1'"
[
  {"destination":"::1","flags":"2098181","gateway":"::1","interface":"","metric":"0","mtu":"16384","netmask":"128","source":"","type":"local"}
]
```

You may also pipe a query as *stdin*. The input will be executed on the `osqueryi` shell and must be well-formed SQL or `osqueryi` meta-commands. Note the added ';' to the query when using *stdin*:

```
echo "SELECT * FROM routes WHERE destination = '::1';" | osqueryi --json
```

## Getting help

`osqueryi` is a modified version of the SQLite shell.
It accepts several meta-commands, prefixed with a '.':

* to list all tables: `.tables`
* to list the schema (columns, types) of a specific table: `.schema table_name` or `pragma table_info(table_name);` for more details
* to list all available commands: `.help`
* to exit the console: `.exit` or `^D`

Here are some example shell commands:

```
osquery> .tables
  => alf_services
  => apps
  => ca_certs
  => etc_hosts
  => interface_addresses
  => interface_details
  => kernel_extensions
  => launchd
  => listening_ports
  => nvram
  => processes
  => routes
[...]

osquery> .schema routes
CREATE VIRTUAL TABLE routes USING routes(
    destination TEXT,
    netmask TEXT,
    gateway TEXT,
    source TEXT,
    flags INTEGER,
    interface TEXT,
    mtu INTEGER,
    metric INTEGER,
    type TEXT
);

osquery> PRAGMA table_info(routes);
+-----+-------------+---------+---------+------------+----+
| cid | name        | type    | notnull | dflt_value | pk |
+-----+-------------+---------+---------+------------+----+
| 0   | destination | TEXT    | 0       |            | 0  |
| 1   | netmask     | TEXT    | 0       |            | 0  |
| 2   | gateway     | TEXT    | 0       |            | 0  |
| 3   | source      | TEXT    | 0       |            | 0  |
| 4   | flags       | INTEGER | 0       |            | 0  |
| 5   | interface   | TEXT    | 0       |            | 0  |
| 6   | mtu         | INTEGER | 0       |            | 0  |
| 7   | metric      | INTEGER | 0       |            | 0  |
| 8   | type        | TEXT    | 0       |            | 0  |
+-----+-------------+---------+---------+------------+----+

osquery> .exit
$
```

The shell does not keep much state, or connect to the `osqueryd` daemon.
If you would like to run queries and log changes to the output or log operating system events, consider deploying a query **schedule** using [osqueryd](using-osqueryd.md).

 > Note: Event publishers are not started by default. To enable event-based tables, use the flag `--disable_events=false`.

`osqueryi` uses an in-memory database by default. To connect to an existing events database, use the flag `--database_path=/var/osquery/osquery.db` (only one process may attach to the database; see [Checking the database sanity](../deployment/debugging.md#checking-the-database-sanity)).
