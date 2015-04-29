An osquery deployment consists of:

* Installing the tools for [OS X](../installation/install-osx) or [Linux](../installation/install-linux)
* Reviewing the [osqueryd](../introduction/using-osqueryd) introduction
* Configuring and starting the osqueryd service (this page)
* Managing and [collecting](log-aggregation) the query results

In the future, osquery tools may allow for **ad-hoc** or distributed queries
that are not part of the configured query schedule and return results
from several selected hosts. Currently, the osqueryd service only accepts
a query schedule from a configuration.

## Configuration components

The osquery "configuration" is read from a config plugin. This plugin is a data retrieval method and is set to **filesystem** by default.
Other retrieval and run-time updating methods may include an HTTL/TLS request.
In each case the response data must be JSON-formatted.

There are several components to a configuration:

* Daemon options and feature settings
* Query Schedule: the set of SQL queries and intervals
* File Change Monitoring: categories and paths of monitored files and directories
* (insert new feature that requires a configuration here!)

There are also "initialization" parameters that control how osqueryd is launched.
These parameters only make sense as command-line arguments since they are used
before a configuration plugin is selected. See the [command line flags](../installation/cli-flags)
overview for a complete list of these parameters.

The default config plugin, **filesystem**, reads from a file and optional directory ".d" based on the filename.

* Linux: **/etc/osquery/osquery.conf** and **/etc/osquery/osquery.conf.d/**
* Mac OS X: **/var/osquery/osquery.conf** and **/var/osquery/osquery.conf.d/**

You may override the **filesystem** plugin's path using `--config_path=/path/to/osquery.conf`. And you may use the ".d/" directory search path based on that custom location.

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

This config tells osqueryd to schedule two queries, **macosx_kextstat** and **foobar**:

* the schedule keys must be unique
* the "interval" specifies query frequency, in seconds

The first query will document changes to an OS X host's kernel extensions, with a query interval of 10 seconds. Consider using osquery's [performance tooling](performance-safety) to understand the performance impact for each query.

The results of your query are cached on disk via [RocksDB](http://rocksdb.org/). On first query run, all of the results are stored in RocksDB. On subsequent runs, only result-set changes are logged to RocksDB.

## Chef Configuration

Here are example chef cookbook recipes and files for OS X and Linux deployments.
Consider improving the recipes using node attributes to further control what
nodes and clients enable osquery. It helps to create a canary or testing set
that implement a separate "testing" configuration. These recipes assume you
are deploying the OS X package or Linux package separately.

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

## osqueryctl helper

To test a deploy or configuration we include a short helper script called osqueryctl.
There are several actions including "start", "stop", and "check-config" that apply
to both OS X and Linux.
