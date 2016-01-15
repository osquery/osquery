osquery
=======

<p align="center">
<img align="center" src="https://osquery.io/assets/logo-dark.png" alt="osquery logo" width="200"/>

<p align="center">
osquery is an operating system instrumentation framework for OS X and Linux. <br/>
The tools make low-level operating system analytics and monitoring both performant and intuitive.

| Platform | Build status  | | | |
|----------|---------------|---|---|---|
OS X 10.9    | [![Build Status](https://jenkins.osquery.io/job/osqueryMasterBuildOSX10.9/badge/icon)](https://jenkins.osquery.io/job/osqueryMasterBuildOSX10.9/) | | **Homepage:** | https://osquery.io
OS X 10.10   | [![Build Status](https://jenkins.osquery.io/job/osqueryMasterBuildOSX10.10/badge/icon)](https://jenkins.osquery.io/job/osqueryMasterBuildOSX10.10/) | | **Downloads:** | https://osquery.io/downloads
OS X 10.11   | [![Build Status](https://jenkins.osquery.io/job/osqueryMasterBuildOSX10.11/badge/icon)](https://jenkins.osquery.io/job/osqueryMasterBuildOSX10.11/) | | **Downloads:** | https://osquery.io/downloads
CentOS 6.5   | [![Build Status](https://jenkins.osquery.io/job/osqueryMasterBuildCentOS6/badge/icon)](https://jenkins.osquery.io/job/osqueryMasterBuildCentOS6/) | | **Tables:** | https://osquery.io/tables
CentOS 7.0   | [![Build Status](https://jenkins.osquery.io/job/osqueryMasterBuildCentOS7/badge/icon)](https://jenkins.osquery.io/job/osqueryMasterBuildCentOS7/) | | **Packs:** | https://osquery.io/packs
Ubuntu 12.04 | [![Build Status](https://jenkins.osquery.io/job/osqueryMasterBuildUbuntu12/badge/icon)](https://jenkins.osquery.io/job/osqueryMasterBuildUbuntu12/) | | **Guide:** | https://osquery.readthedocs.org
Ubuntu 14.04 | [![Build Status](https://jenkins.osquery.io/job/osqueryMasterBuildUbuntu14/badge/icon)](https://jenkins.osquery.io/job/osqueryMasterBuildUbuntu14/) | | [![Slack Status](https://osquery-slack.herokuapp.com/badge.svg)](https://osquery-slack.herokuapp.com) | https://osquery.slack.com

#### What is osquery?

osquery exposes an operating system as a high-performance relational database. This allows you to write SQL-based queries to explore operating system data. With osquery, SQL tables represent abstract concepts such as running processes, loaded kernel modules, open network connections, browser plugins, hardware events or file hashes.

SQL tables are implemented via a simple plugin and extensions API. A variety of tables already exist and more are being written: [https://osquery.io/tables](https://osquery.io/tables). To best understand the expressiveness that is afforded to you by osquery, consider the following SQL queries:


List the [`users`](https://osquery.io/docs/tables/#users):
```sql
SELECT * FROM users;
```

Check the [`processes`](https://osquery.io/docs/tables/#processes) that have a deleted executable:
```sql
SELECT * FROM processes WHERE on_disk = 0;
```

Get the process name, port, and PID, for processes listening on all interfaces:
```sql
SELECT DISTINCT processes.name, listening_ports.port, processes.pid
  FROM listening_ports JOIN processes USING (pid)
  WHERE listening_ports.address = '0.0.0.0';
```

Find every OS X LaunchDaemon that launches an executable and keeps it running:
```sql
SELECT name, program || program_arguments AS executable
  FROM launchd
  WHERE (run_at_load = 'true' AND keep_alive = 'true')
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
* performed on an ad-hoc basis to explore operating system state using the [osqueryi](https://osquery.readthedocs.org/en/latest/introduction/using-osqueryi/) shell
* executed via a [scheduler](https://osquery.readthedocs.org/en/latest/introduction/using-osqueryd/) to monitor operating system state across a set of hosts
* launched from custom applications using osquery Thrift APIs

#### Downloads / Install

For latest stable and nightly builds for OS X and Linux (deb/rpm), as well as yum and apt repository information visit [https://osquery.io/downloads](https://osquery.io/downloads/). For installation information for FreeBSD, which is supported by the osquery community, see the [wiki](https://osquery.readthedocs.org/en/latest/installation/install-freebsd/).

##### Building from source

[Building](https://osquery.readthedocs.org/en/latest/development/building/) osquery from source is encouraged! Join our developer community by giving us feedback in Github issues or submitting pull requests!

#### File Integrity Monitoring (FIM)

osquery provides several [FIM features](http://osquery.readthedocs.org/en/stable/deployment/file-integrity-monitoring/) too! Just as OS concepts are represented in tabular form, the daemon can track OS events and later expose them in a table. Tables like [`file_events`](https://osquery.io/docs/tables/#file_events) or [`yara_events`](https://osquery.io/docs/tables/#yara_events) can be selected to retrieve buffered events.

The configuration allows you to organize files and directories for monitoring. Those sets can be paired with lists of YARA signatures or configured for additional monitoring such as access events.

##### Process and socket auditing

There are several forms of [eventing](http://osquery.readthedocs.org/en/stable/development/pubsub-framework/) in osquery along with file modifications and accesses. These range from disk mounts, network reconfigurations, hardware attach and detaching, and process starting. For a complete set review the table documentation and look for names with the `_events` suffix.

#### Vulnerabilities

Facebook has a [bug bounty](https://www.facebook.com/whitehat/) program that includes osquery. If you find a security vulnerability in osquery, please submit it via the process outlined on that page and do not file a public issue. For more information on finding vulnerabilities in osquery, see a recent blog post about [bug-hunting osquery](https://www.facebook.com/notes/facebook-bug-bounty/bug-hunting-osquery/954850014529225).

#### Learn more

Read the [launch blog post](https://code.facebook.com/posts/844436395567983/introducing-osquery/) for background on the project.
If you're interested in learning more about osquery, visit the [users guide](https://osquery.readthedocs.org/) and browse our RFC-labeled Github issues. Development and usage discussion is happing in the osquery Slack, grab an invite automatically: [https://osquery-slack.herokuapp.com/](https://osquery-slack.herokuapp.com/)!
