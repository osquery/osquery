# osquery

<p align="center">
<img alt="osquery logo" width="200"
src="https://github.com/facebook/osquery/raw/master/docs/img/logo-2x-dark.png" />
</p>

<p align="center">
osquery is a SQL powered operating system instrumentation, monitoring, and analytics framework.
<br>
Available for Linux, macOS, Windows and FreeBSD.
</p>

| Platform | Build status  | | | |
|----------|---------------|---|---|---|
|MacOS 10.14  | [![Build Status](https://dev.azure.com/trailofbits/osquery/_apis/build/status/osquery?branchName=master&jobName=macOS)](https://dev.azure.com/trailofbits/osquery/_build/latest?definitionId=6&branchName=master) | | **Homepage:** | https://osquery.io
|Ubuntu 18.04 | [![Build Status](https://dev.azure.com/trailofbits/osquery/_apis/build/status/osquery?branchName=master&jobName=Linux)](https://dev.azure.com/trailofbits/osquery/_build/latest?definitionId=6&branchName=master) | | **Downloads:** | https://osquery.io/downloads
|Windows Server 2016 | [![Build Status](https://dev.azure.com/trailofbits/osquery/_apis/build/status/osquery?branchName=master&jobName=Windows)](https://dev.azure.com/trailofbits/osquery/_build/latest?definitionId=6&branchName=master) | | **Tables:** | https://osquery.io/schema
|FreeBSD 11 | N/A | | **Packs:** | [https://osquery.io/packs](https://github.com/facebook/osquery/tree/master/packs)
| | | | **Guide:** | https://osquery.readthedocs.org
| | | | [![Slack Status](https://osquery-slack.herokuapp.com/badge.svg)](https://osquery-slack.herokuapp.com) | https://osquery-slack.herokuapp.com

## What is osquery?

osquery exposes an operating system as a high-performance relational database.  This allows you to
write SQL-based queries to explore operating system data.  With osquery, SQL tables represent
abstract concepts such as running processes, loaded kernel modules, open network connections,
browser plugins, hardware events or file hashes.

SQL tables are implemented via a simple plugin and extensions API. A variety of tables already exist
and more are being written: [https://osquery.io/schema](https://osquery.io/schema/). To best
understand the expressiveness that is afforded to you by osquery, consider the following SQL
queries:

List the [`users`](https://osquery.io/schema/current#users):
```sql
SELECT * FROM users;
```

Check the [`processes`](https://osquery.io/schema/current#processes) that have a deleted executable:
```sql
SELECT * FROM processes WHERE on_disk = 0;
```

Get the process name, port, and PID, for processes listening on all interfaces:
```sql
SELECT DISTINCT processes.name, listening_ports.port, processes.pid
  FROM listening_ports JOIN processes USING (pid)
  WHERE listening_ports.address = '0.0.0.0';
```

Find every macOS LaunchDaemon that launches an executable and keeps it running:
```sql
SELECT name, program || program_arguments AS executable
  FROM launchd
  WHERE (run_at_load = 1 AND keep_alive = 1)
  AND (program != '' OR program_arguments != '');
```

Check for ARP anomalies from the host's perspective:

```sql
SELECT address, mac, COUNT(mac) AS mac_count
  FROM arp_cache GROUP BY mac
  HAVING count(mac) > 1;
```

Alternatively, you could also use a SQL sub-query to accomplish the same result:

```sql
SELECT address, mac, mac_count
  FROM
    (SELECT address, mac, COUNT(mac) AS mac_count FROM arp_cache GROUP BY mac)
  WHERE mac_count > 1;
```

These queries can be:
* performed on an ad-hoc basis to explore operating system state using the
  [osqueryi](https://osquery.readthedocs.org/en/latest/introduction/using-osqueryi/) shell
* executed via a [scheduler](https://osquery.readthedocs.org/en/latest/introduction/using-osqueryd/)
  to monitor operating system state across a set of hosts
* launched from custom applications using osquery Thrift APIs

## Download & Install

To download the latest stable builds and for repository information and installation instructions
visit [https://osquery.io/downloads](https://osquery.io/downloads/).

## Build from source

Building osquery from source is encouraged! Check out our [build guide](BUILD.md).

Also check out our [contributing guide](CONTRIBUTING.md) and join the community on [Slack](https://slack.osquery.io).

## License

By contributing to osquery you agree that your contributions will be licensed as defined on the
LICENSE file.

## Vulnerabilities

We keep track of security announcements in our tagged version release notes on GitHub. We aggregate
these into [SECURITY.md](SECURITY.md) too.

Facebook has a [bug bounty](https://www.facebook.com/whitehat/) program that includes osquery. If
you find a security vulnerability in osquery, please submit it via the process outlined on that page
and **do not file a public issue**. For more information on finding vulnerabilities in osquery, see
our blog post [Bug Hunting
osquery](https://www.facebook.com/notes/facebook-bug-bounty/bug-hunting-osquery/954850014529225).

## Learn more

If you're interested in learning more about osquery read the [launch blog
post](https://code.facebook.com/posts/844436395567983/introducing-osquery/) for background on the
project, visit the [users guide](https://osquery.readthedocs.org/).

Development and usage discussion is happening in the osquery Slack, grab an invite automatically
[here](https://slack.osquery.io)!
