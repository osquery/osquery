osquery
=======
Platform | Build status
---------|-------------
OS X 10.10      | [![Build Status](http://jenkins.osquery.io/job/osqueryMasterBuildOSX/badge/icon)](http://jenkins.osquery.io/job/osqueryMasterBuildOSX/)
CentOS 6.5      | [![Build Status](http://jenkins.osquery.io/job/osqueryMasterBuildCentOS6/badge/icon)](http://jenkins.osquery.io/job/osqueryMasterBuildCentOS6/)
CentOS 7.0      | [![Build Status](http://jenkins.osquery.io/job/osqueryMasterBuildCentOS7/badge/icon)](http://jenkins.osquery.io/job/osqueryMasterBuildCentOS7/)
Ubuntu 12.04 LTS | [![Build Status](http://jenkins.osquery.io/job/osqueryMasterBuildUbuntu12/badge/icon)](http://jenkins.osquery.io/job/osqueryMasterBuildUbuntu12/)
Ubuntu 14.04 LTS | [![Build Status](http://jenkins.osquery.io/job/osqueryMasterBuildUbuntu14/badge/icon)](http://jenkins.osquery.io/job/osqueryMasterBuildUbuntu14/)


osquery is an operating system instrumentation framework for OSX and Linux. osquery makes low-level operating system analytics and monitoring both performant and intuitive.

osquery exposes an operating system as a high-performance relational database. This allows you to write SQL-based queries to explore operating system data. With osquery, SQL tables represent abstract concepts such as

- running processes
- loaded kernel modules
- open network connections

SQL tables are implemented via an easily extendable API. A variety of tables already exist and more are being written.

To best understand the expressiveness that is afforded to you by osquery, consider the following SQL queries:

```sql
--------------------------------------------------------
-- get the name, pid and attached port of all processes
-- which are listening on all interfaces
--------------------------------------------------------
SELECT DISTINCT
  process.name,
  listening.port,
  process.pid
FROM processes AS process
JOIN listening_ports AS listening
ON process.pid = listening.pid
WHERE listening.address = '0.0.0.0';
```

```sql
--------------------------------------------------------
-- find every launchdaemon on an OS X host which
--   * launches an executable when the operating
--     system starts
--   * keeps the executable running
-- return the name of the launchdaemon and the full
-- path (with arguments) of the executable to be ran.
--------------------------------------------------------
SELECT
  name,
  program || program_arguments AS executable
FROM launchd
WHERE
  (run_at_load = 'true' AND keep_alive = 'true')
AND
  (program != '' OR program_arguments != '');
```

These queries can be:
- performed on an ad-hoc basis to explore operating system state
- executed via a scheduler to monitor operating system state across a distributed set of hosts over time
- launched from custom applications using osquery APIs

## Install

### OS X

The easiest way to install osquery on OS X is via Homebrew. Check the [Homebrew](http://brew.sh/) homepage for installation instructions.

Run the following:

```
brew update
brew install osquery
```

To update osquery:

```
brew update
brew upgrade osquery
```

### Linux

We don't currently supply pre-built osquery packages for Linux. We do, however, provide Vagrant VMs which allow you to easily create packages for Ubuntu 12.04+ and CentOS 6.5. Check out the wiki's [installation guide](https://github.com/facebook/osquery/wiki/install-linux) for more information.

If you're trying to build osquery on a different, currently unsupported operating system, please refer to the [building the code guide](https://github.com/facebook/osquery/wiki/building-the-code) for help.

## Vulnerabilities

Facebook has a [bug bounty](https://www.facebook.com/whitehat/) program which osquery participates in. If you find a vulnerability in osquery, please submit it via the process outlined on that page and do not file a public issue.

For more information on finding vulnerabilities in osquery, see a recent blog post about bug-hunting osquery: https://www.facebook.com/notes/facebook-bug-bounty/bug-hunting-osquery/954850014529225

## Learn more

Read the [launch blog post](https://code.facebook.com/posts/844436395567983/introducing-osquery/) for background on the project.

If you're interested in learning more about osquery, visit the [wiki](https://github.com/facebook/osquery/wiki).

