osquery
=======

<a target="_blank" href="https://magnum.travis-ci.com/facebook/osquery"><img src="https://magnum.travis-ci.com/facebook/osquery.svg?token=MvaZkzWisgsA98PZfNC7&branch=master"></a>

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

## Learn more

If you're interested in learning more about osquery, visit the [wiki](https://github.com/facebook/osquery/wiki).
