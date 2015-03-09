`osqueryi` is the interactive query console which comes with osquery.

## Executing SQL queries

osqueryi lets you run commands and query osquery tables. See the [table API](http://osquery.io/tables/) for a complete list of tables, types, and column descriptions.

For SQL syntax help, see [SQL as understood by SQLite](http://www.sqlite.org/lang.html).

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

## Getting help

Administrative commands are prefixed with a '.'

* to list all tables: `.tables`
* to list the schema (columns, types) of a specific table: `pragma table_info(table_name);`
* to list all available commands: `.help`
* to exit the console: `.exit` or `^D`

Here is some example shell command usage:

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

osquery> .help
.bail ON|OFF           Stop after hitting an error.  Default OFF
.echo ON|OFF           Turn command echo on or off
.exit                  Exit this program
.explain ?ON|OFF?      Turn output mode suitable for EXPLAIN on or off.
                         With no args, it turns EXPLAIN on.
.header(s) ON|OFF      Turn display of headers on or off
.help                  Show this message
.indices ?TABLE?       Show names of all indices
                         If TABLE specified, only show indices for tables
                         matching LIKE pattern TABLE.
.mode MODE ?TABLE?     Set output mode where MODE is one of:
                         csv      Comma-separated values
                         column   Left-aligned columns.  (See .width)
                         html     HTML <table> code
                         line     One value per line
                         list     Values delimited by .separator string
                         pretty   Pretty printed SQL results
                         tabs     Tab-separated values
                         tcl      TCL list elements
.nullvalue STRING      Use STRING in place of NULL values
.print STRING...       Print literal STRING
.quit                  Exit this program
.schema ?TABLE?        Show the CREATE statements
                         If TABLE specified, only show tables matching
                         LIKE pattern TABLE.
.separator STRING      Change separator used by output mode and .import
.show                  Show the current values for various settings
.stats ON|OFF          Turn stats on or off
.tables ?TABLE?        List names of tables
                         If TABLE specified, only list tables matching
                         LIKE pattern TABLE.
.trace FILE|off        Output each SQL statement as it is run
.width NUM1 NUM2 ...   Set column widths for "column" mode
.timer ON|OFF          Turn the CPU timer measurement on or off

osquery> .exit
$ 
```
