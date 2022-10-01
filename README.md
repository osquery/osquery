# osquery

<p align="center">
<img alt="osquery logo" width="200"
src="https://github.com/osquery/osquery/raw/master/docs/img/logo-2x-dark.png" />
</p>

<p align="center">
osquery is a SQL powered operating system instrumentation, monitoring, and analytics framework.
<br>
Available for Linux, macOS, and Windows.
</p>

## Information and resources

- Homepage: [osquery.io](https://osquery.io)
- Downloads: [osquery.io/downloads](https://osquery.io/downloads)
- Documentation: [ReadTheDocs](https://osquery.readthedocs.org)
- Stack Overflow: [Stack Overflow questions](https://stackoverflow.com/questions/tagged/osquery)
- Table Schema: [osquery.io/schema](https://osquery.io/schema)
- Query Packs: [osquery.io/packs](https://github.com/osquery/osquery/tree/master/packs)
- Slack: [Browse the archives](https://chat.osquery.io/c/general) or [Join the conversation](https://join.slack.com/t/osquery/shared_invite/zt-h29zm0gk-s2DBtGUTW4CFel0f0IjTEw)
- Build Status: [![GitHub Actions Build Status](https://github.com/osquery/osquery/workflows/build/badge.svg)](https://github.com/osquery/osquery/actions?query=workflow%3Abuild+branch%3Amaster) [![Coverity Scan Build Status](https://scan.coverity.com/projects/13317/badge.svg)](https://scan.coverity.com/projects/osquery) [![Documentation Status](https://readthedocs.org/projects/osquery/badge/?version=latest)](https://osquery.readthedocs.io/en/latest/?badge=latest)
- CII Best Practices: [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/3125/badge)](https://bestpractices.coreinfrastructure.org/projects/3125)

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

- performed on an ad-hoc basis to explore operating system state using the
  [osqueryi](https://osquery.readthedocs.org/en/latest/introduction/using-osqueryi/) shell
- executed via a [scheduler](https://osquery.readthedocs.org/en/latest/introduction/using-osqueryd/)
  to monitor operating system state across a set of hosts
- launched from custom applications using osquery Thrift APIs

## Download & Install

To download the latest stable builds and for repository information
and installation instructions visit
[https://osquery.io/downloads](https://osquery.io/downloads/).

We use a simple numbered versioning scheme `X.Y.Z`, where X is a major version, Y is a minor, and Z is a patch.
We plan minor releases roughly every two months. These releases are tracked on our [Milestones](https://github.com/osquery/osquery/milestones) page. A patch release is used when there are unforeseen bugs with our minor release and we need to quickly patch.
A rare 'revision' release might be used if we need to change build configurations.

Major, minor, and patch releases are tagged on GitHub and can be viewed on the [Releases](https://github.com/osquery/osquery/releases) page.
We open a new [Release Checklist](https://github.com/osquery/osquery/blob/master/.github/ISSUE_TEMPLATE/New_Release.md) issue when we prepare a minor release. If you are interested in the status of a release, please find the corresponding checklist issue, and note that the issue will be marked closed when we are finished the checklist.
We consider a release 'in testing' during the period of hosting new downloads on our website and adding them to our hosted repositories.
We will mark the release as 'stable' on GitHub when enough testing has occurred, this usually takes two weeks.

## Build from source

Building osquery from source is encouraged! Check out our [build
guide](https://osquery.readthedocs.io/en/latest/development/building/). Also
check out our [contributing guide](CONTRIBUTING.md) and join the
community on [Slack](https://join.slack.com/t/osquery/shared_invite/zt-h29zm0gk-s2DBtGUTW4CFel0f0IjTEw).

## License

By contributing to osquery you agree that your contributions will be
licensed as defined on the LICENSE file.

## Vulnerabilities

We keep track of security announcements in our tagged version release
notes on GitHub. We aggregate these into [SECURITY.md](SECURITY.md)
too.

## Learn more

The osquery documentation is available
[online](https://osquery.readthedocs.org). Documentation for older
releases can be found by version number, [as
well](https://readthedocs.org/projects/osquery/).

If you're interested in learning more about osquery read the [launch
blog
post](https://code.facebook.com/posts/844436395567983/introducing-osquery/)
for background on the project, visit the [users
guide](https://osquery.readthedocs.org/).

Development and usage discussion is happening in the osquery Slack, grab an invite
[here](https://join.slack.com/t/osquery/shared_invite/zt-h29zm0gk-s2DBtGUTW4CFel0f0IjTEw)!
