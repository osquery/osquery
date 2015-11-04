An osquery deployment consists of:

* Installing the tools for [OS X](../installation/install-osx.md) or
	[Linux](../installation/install-linux.md)
* Reviewing the [osqueryd](../introduction/using-osqueryd.md) introduction
* Configuring and starting the **osqueryd** service (this page)
* Managing and [collecting](log-aggregation.md) the query results

In the future, osquery tools may allow for **ad-hoc** or distributed queries
that are not part of the configured query schedule and return results
from several selected hosts. Currently, the **osqueryd** service only accepts
a query schedule from a configuration.

## Configuration components

The osquery "configuration" is read from a config plugin. This plugin is a data
retrieval method and is set to **filesystem** by default.  Other retrieval and
run-time updating methods may include an HTTP/TLS request using the **tls**
config plugin. In all cases the response data must be JSON-formatted.

There are several components contributing to a configuration:

* Daemon options and feature settings
* Query Schedule: the set of SQL queries and intervals
* File Change Monitoring: categories and paths of monitored files and
	directories
* (insert new feature that requires a configuration here!)

There are also "initialization" parameters that control how osqueryd is
launched.  These parameters only make sense as command-line arguments since
they are used before a configuration plugin is selected. See the [command line
flags](../installation/cli-flags.md) overview for a complete list of these
parameters.

The default config plugin, **filesystem**, reads from a file and optional
directory ".d" based on the filename.

* Linux: **/etc/osquery/osquery.conf** and **/etc/osquery/osquery.conf.d/**
* Mac OS X: **/var/osquery/osquery.conf** and **/var/osquery/osquery.conf.d/**

You may override the **filesystem** plugin's path using
`--config_path=/path/to/osquery.conf`. You may also use the ".d/" directory
search path based on that custom location.

Here is an example config that includes options and the query schedule:

```json
{
  "options": {
    "host_identifier": "hostname",
    "schedule_splay_percent": 10
  },
  "schedule": {
    "macosx_kextstat": {
      "query": "SELECT * FROM kernel_extensions;",
      "interval": 10
    },
    "foobar": {
      "query": "SELECT foo, bar, pid FROM foobar_table;",
      "interval": 600
    }
  }
}
```

This config tells osqueryd to schedule two queries, **macosx_kextstat** and
**foobar**:

* the schedule keys must be unique
* the "interval" specifies query frequency (in seconds)

The first query will document changes to the OS X host's kernel extensions,
with a query interval of 10 seconds. Consider using osquery's [performance
tooling](performance-safety.md) to understand the performance impact for each
query.

The results of your query are cached on disk using
[RocksDB](http://rocksdb.org/). On the first query run, all of the results are
stored in RocksDB. On subsequent runs, only result-set changes are logged to
RocksDB.

Scheduled queries can also set: `"removed":false` and `"snapshot":true`. See
the next section on [logging](logging.md) to learn how query options affect the
output.

## Chef Configuration

Here are example chef cookbook recipes and files for OS X and Linux
deployments.  Consider improving the recipes using node attributes to further
control what nodes and clients enable osquery. It helps to create a canary or a
testing set that implements a separate "testing" configuration. These recipes
assume you are deploying the OS X package or the Linux package separately.

### Chef OS X

Consider the default recipe:

```ruby
# Domain used by the OS X LaunchDaemon.
domain = 'com.facebook.osquery.osqueryd'

directory '/var/osquery' do
  recursive true
  mode 0755
end

template "/Library/LaunchDaemons/#{domain}.plist" do
  source 'launchd.plist.erb'
  mode '0444'
  owner 'root'
  group 'wheel'
  notifies :restart, "service[#{domain}]"
end

cookbook_file "/etc/newsyslog.d/#{domain}.conf" do
  source "#{domain}.conf"
  mode 0644
  owner 'root'
  group 'wheel'
end

cookbook_file '/var/osquery/osquery.conf' do
  source 'osquery.conf'
  mode 0444
  owner 'root'
  group 'wheel'
  notifies :restart, "service[#{domain}]"
end

service domain do
  action [:enable, :start]
end
```

And the following files/templates used by the recipe:

**templates/default/launchd.plist.erb**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>KeepAlive</key>
  <true/>
  <key>Disabled</key>
  <false/>
  <key>OnDemand</key>
  <false/>
  <key>Label</key>
  <string><%= domain %></string>
  <key>Program</key>
        <string>/usr/local/bin/osqueryd</string>
  <key>RunAtLoad</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>60</integer>
</dict>
</plist>
```

**files/default/com.facebook.osquery.osqueryd.conf**
```
# logfilename                         [owner:group]  mode count size   when  flags [/pid_file] [sig_num]
/var/log/osquery/osqueryd.results.log root:wheel     600  2     10000  *     NZ
```

**files/default/osquery.conf**
```json
{
  "options": {
    "host_identifier": "hostname",
    "schedule_splay_percent": 10
  },
  "schedule": {
    "macosx_kextstat": {
      "query": "SELECT * FROM kernel_extensions;",
      "interval": 10
    }
  }
}
```

### Chef Linux

Consider the default recipe:

```ruby
# Service name installed by the osquery package.
service_name = 'osqueryd'

cookbook_file '/etc/osquery/osquery.conf' do
  source 'osquery.conf'
  mode 0444
  owner 'root'
  group 'wheel'
  notifies :restart, "service[#{service_name}]"
end

service service_name do
  action [:enable, :start]
end
```

And the same configuration file from the OS X example is appropriate.

## Query Packs

Configuration supports sets, called packs, of queries that help define your
schedule. Packs are distributed with osquery and labeled based on broad
categories of information and visibility. For example, a "compliance" pack will
include queries that check for changes in locked down operating system features
and user settings. A "vulnerability management" pack may perform general asset
management queries that build event logs around package and software install
changes.

In an osquery configuration JSON, packs are defined as a top-level-key and
consist of pack name to pack content JSON data structures.

```json
{
  "schedule": {...},
  "packs": {
    "internal_stuff": {
      "discovery": [
        "select pid from processes where name = 'ldap';"
      ],
      "platform": "linux",
      "version": "1.5.2",
			"queries": {
        "active_directory": {
          "query": "select * from ad_config;",
          "interval": "1200",
          "description": "Check each user's active directory cached settings."
        }
      }
    }
  }
}
```

The pack value may also be a string, such as:

```json
{
  "packs": {
    "external_pack": "/path/to/external_pack.conf",
    "internal_stuff": {
      [...]
    }
  }
}
```

If using a string instead of an inline JSON dictionary the configuration plugin will be asked to "generate" that resource. In the case of the default **filesystem** plugin, these strings are considered paths.

Queries added to the schedule from packs inherit the pack name as part of the scheduled query name identifier. For example, consider the embedded `active_directory` query above, it is in the `internal_stuff` pack so the scheduled query name becomes: `pack_internal_stuff_active_directory`. The delimiter can be changed using the `--pack_delimiter=_`, see the [CLI Options](../installation/cli-flags.md) for more details.

### Discovery queries

Discovery queries are a feature of query packs that make it much easier to monitor services at scale. Consider that there are some groups of scheduled
queries which should only be run on a host when a condition is true. For
example, perhaps you want to write some queries to monitor MySQL. You've made a
pack called "mysql" and now you only want the queries in that pack to execute
if the `mysqld` program is running on the host.

Without discovery queries, you could have your configuration management write a
different configuration file for your MySQL tier. Unfortunately, however, this
requires you to know the complete set of hosts in your environment which are
running MySQL. This is problematic, especially if engineers in your environment
can install arbitrary software on arbitrary hosts. If MySQL is installed on a
non-standard host, you have no way to know. Therefore, you cannot schedule your MySQL pack on those hosts through configuration management logic.

One solution to this problem is discovery queries.

Query packs allow you to define a set of osquery queries which control whether
or not the pack will execute. Discovery queries are represented by the
top-level "discovery" key-word in a pack. The value should be a list of osquery
queries. If all of the queries return more than zero rows, then the queries are
added to the query schedule. This allows you to distribute configurations for
many services and programs, while ensuring that only relevant queries will be
executing on your host.

You don't need to define any discovery queries for a pack. If no discovery
queries are defined, then the pack will always execute.

Discovery queries look like:

```json
{
  "discovery": [
    "select pid from processes where name = 'foobar';",
    "select count(*) from users where username like 'www%';"
  ],
	"queries": {}
}
```

In the above example, the pack will only execute on hosts which are running
processes called "foobar" or has users that start with "www".

Discovery queries are refreshed for all packs every 60 minutes. You can
change this value via the `pack_refresh_interval` configuration option.

**Where do packs go?**

The default way to define a query pack is in the main configuration file.
Consider the following example:

```json
{
  "options": {
    "enable_monitor": "true"
  },
  "packs": {
    "foo": {
      "queries": {}
    },
    "bar": {
      "queries": {}
    }
  }
}
```

Alternatively, however, you can also define the value of a pack as a raw
string. Consider the following example:

```json
{
  "options": {
    "enable_monitor": "true"
  },
  "packs": {
    "foo": "/tmp/foo.json",
    "bar": "/tmp/bar.json"
  }
}
```

In the above example, the packs are defined using a local filesystem path.
When osquery's config parser is provided a string instead of inline dictionary the active config plugin is called to resolve what should be done to go from `/tmp/foo.json` to the actual content of the pack. See [configuration plugin](../development/config-plugins.md) development for more information on packs.

### Options

In addition to discovery and queries, a pack may contain a **platform** key
and a **version** key. Specifying platform allows you to specify that the pack
should only be executed on "linux", "darwin", etc.

In practice, this looks like:

```json
{
	"platform": "any",
	"version": "1.5.0",
	"queries": {}
}
```

Additionally, you can specify platform and version on individual queries in
a pack. For example:

```json
{
	"platform": "any",
	"version": "1.5.0",
	"queries": {
		"info": {
			"query": "select * from osquery_info;",
			"interval": 60
		},
		"packs": {
			"query": "select * from osquery_packs;",
			"interval": 60,
			"version": "1.5.2"
		}
	}
}
```

In this example, the **info** query will run on osquery version 1.5.0 and above
since the minimum version defined for the global pack is 1.5.0. The **packs**
query, however, defines an additional version constraint, therefore the **packs** query will only run on osquery version 1.5.2 and above.

**Where can I get more existing packs?**

We release (and bundle alongside RPMs/DEBs/PKGs/etc.) query packs that emit high signal events as well as event data that is worth storing in the case of future incidents and security events. The queries within each pack will be performance tested and well-formed (JOIN, select-limited, etc.). But it is always an exercise for the user to make sure queries are useful and are not impacting performance critical hosts. You can find the query packs that are released by the osquery team documented at [https://osquery.io/docs/packs] and the content in [**/packs**](https://github.com/facebook/osquery/blob/master/packs) within the osquery repository.

**How do I modify the default options in the provided packs?**

We don't offer a built-in way to modify the default intervals / options in the
supplied query packs. Fortunately, however, packs are just JSON. Therefore, it
would be rather trivial to write a tool which reads in pack JSON, modifies it
in some way, then re-writes the JSON.

## osqueryctl helper

To test a deploy or configuration we include a short helper script called **osqueryctl**. There are several actions including "start", "stop", and "config-check" that apply to both OS X and Linux.
