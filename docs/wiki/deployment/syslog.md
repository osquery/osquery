# Reading syslog with osquery

osquery 1.7.3 introduced support for consuming and querying the macOS system log via Apple System Log (ASL). osquery 1.7.4 introduced support for the Linux syslog via **rsyslog**. This document explains how to configure and use these syslog tables.

## macOS Syslog

On macOS, the `asl` virtual table makes use of Apple's ASL store, querying this structured store using the routines provided in [`asl.h`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/asl_set.3.html).

### macOS Configuration

No configuration is required to begin using the `asl` table. Note, however, that the table is only able to query logs that are available in the ASL store.

If your target logs are not already being sent to the ASL store by your current configuration, take a look at the [man page](https://www.unix.com/man-page/osx/5/asl.conf/) for `asl.conf`, and use the `store` action to ensure your logs of interest are available in the store. `asl.conf` is also responsible for the rotation and retention settings of the ASL store.

The configuration for `/var/log/install.log` and `/var/log/commerce.log` is hardcoded into the Apple provided syslog binaries, and we are not aware of a way to configure ASL to send these logs to the store.

### macOS Usage

The `asl` table can be queried like any other osquery table. It exposes many of the columns of structured data from the ASL store, and other additional columns are made available as a JSON dictionary in the `extra` column. Use `.schema asl` in the `osqueryi` shell to see the schema.

Basic query predicates (`<`, `<=`, `=`, `>=`, `>`) are able to be efficiently queried in the store. The `LIKE` predicate is also supported, however it must be tested after applying all other predicates and reading logs from the store. For performance reasons, it is suggested to use at least one basic predicate in a query against the `asl` table. For example,

```sql
SELECT time, message FROM asl WHERE facility = 'authpriv' AND sender = 'sudo' AND message LIKE '%python%';
```

## Linux Syslog

On Linux, the `syslog` table queries logs forwarded over a named pipe from a properly configured `rsyslogd`. This method was chosen to support the widest range of Linux flavors (in theory, anything running at least `rsyslogd` version 5, and tested with Ubuntu 12+, CentOS 7.1+, RHEL 7.2+), and to ensure that existing syslog routines and configurations are not modified. As syslog is ingested into osquery, it is written into the backing store (RocksDB) and made available for querying.

Alternatively you can also use **syslog-ng** to forward log messages to osquery.

> NOTICE: the Syslog ingestion is NOT recommended for hosts functioning as syslog aggregators. We have not tested ingestion for massive-throughput or lossless setups.

### Linux Configuration

The `syslog` table requires additional configuration before it can be used. Append `--enable_syslog` to your command line arguments or `--flagfile` to enable osquery's `syslog` event publisher thread.

When an osquery process that supports the `syslog` table starts up, it will attempt to create (and properly set permissions for) a named pipe for `rsyslogd` to write to. The path for this pipe is determined by the configuration flag `--syslog_pipe_path` (defaults to `/var/osquery/syslog_pipe`). If verbose logging is turned on, you should see a status message indicating whether osquery was able to successfully open the pipe for reading.

Permissions for the pipe must at least allow `rsyslogd` to read/write, and osquery to read. For security, it is advised that the least possible privileges are enabled to allow this.

Once the named pipe is created, `rsyslogd` must be configured to write logs to the pipe. Add the following to your **rsyslog** configuration files (usually located in `/etc/rsyslog.conf` or `/etc/rsyslog.d/`):

#### rsyslog versions < 7

```t
$template OsqueryCsvFormat, "%timestamp:::date-rfc3339,csv%,%hostname:::csv%,%syslogseverity:::csv%,%syslogfacility-text:::csv%,%syslogtag:::csv%,%msg:::csv%\n"
*.* |/var/osquery/syslog_pipe;OsqueryCsvFormat
```

#### rsyslog versions >= 7

The above configuration should also work, but **rsyslog** strongly recommends using the new style configuration syntax.

```
template(
  name="OsqueryCsvFormat"
  type="string"
  string="%timestamp:::date-rfc3339,csv%,%hostname:::csv%,%syslogseverity:::csv%,%syslogfacility-text:::csv%,%syslogtag:::csv%,%msg:::csv%\n"
)
*.* action(type="ompipe" Pipe="/var/osquery/syslog_pipe" template="OsqueryCsvFormat")
```

#### All versions

`rsyslogd` must be restarted for the changes to take effect. On many systems, this can be achieved by `sudo service rsyslog restart`.

> NOTICE: `rsyslogd` will only check once, at startup, whether it can write to the pipe. If `rsyslogd` cannot write to the pipe, it will not retry until restart.

#### Other configuration

Configuration flags control the retention of syslog logs. `--syslog_events_expiry` (default 30 days) defines how long (in seconds) to keep logs. `--syslog_events_max` (default 100,000) sets a maximum number of logs to retain (oldest logs are deleted first if this number is surpassed).

#### Configuring syslog-ng

Configuring osquery to receive logs from syslog-ng is no different from rsyslog, so here only the syslog-ng part is shown. Add the following to your **syslog-ng** configuration files (usually located in `/etc/syslog-ng/syslog-ng.conf` or `/etc/syslog-ng/conf.d/`):

```t
# Reformat log messages in a format that osquery accepts
rewrite r_csv_message {
  set("$MESSAGE", value("CSVMESSAGE") );
  subst("\"","\"\"", value("CSVMESSAGE"), flags(global) );
};

template t_csv {
template("\"${ISODATE}\",\"${HOST}\",\"${LEVEL_NUM}\",\"${FACILITY}\",\"${PROGRAM}\",\"${CSVMESSAGE}\"\n");
 template_escape(no);
};

# Sends messages to osquery
destination d_osquery {
  pipe("/var/osquery/syslog_pipe" template(t_csv));
};

# Stores messages sent to osquery in a log file, useful for troubleshooting
 destination d_osquery_copy {
  file("/var/log/csv_osquery" template(t_csv));
};

# Log path to send incoming messages to osquery
 log {
 source(s_sys);
 rewrite(r_csv_message);
 destination(d_osquery);
 # destination(d_osquery_copy);
};
```

The rewrite is needed to make sure that quotation marks are escaped. The template re-formats the messages as expected by osquery. Binaries provided by the osquery project expect syslog messages in this pipe: you might need to change the location if you compiled osquery yourself. If you want to see what messages are sent to osquery you can uncomment the `d_osquery_copy` destination in the log path. The `s_sys` source refers to your local log messages and might be different on your system (this example is from CentOS).

### Usage

Once configuration is complete, the `syslog` table can be queried like any other osquery table. It's schema can be viewed with `.schema syslog`.

> NOTICE: only logs produced after this table was properly configured (and while osquery is running) will be available for querying.

If no logs are available to query, try turning on verbose logging, and see [issue #1964](https://github.com/osquery/osquery/issues/1964) for debugging suggestions.
