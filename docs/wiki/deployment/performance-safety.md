Performance is a core feature of osquery's visibility capability. However, the tool is very powerful and there are opportunities to ruin the performance guarantees with ill-formed queries.

This guide provides an overview and tutorial for assuring performance of the osquery scheduled queries, as well as performance-centric development practices/enforcements.

## Testing query performance

The osquery tooling provides a full-featured profiling script. The script can evaluate table, query, and scheduled query performance on a system. Before scheduling a set of queries on your enterprise hosts, it is best practice to measure the expected performance impact.

Consider the following `osquery.conf`:

```json
{
  "schedule": {
    "alf_services": {
      "query": "SELECT service, process FROM alf_services WHERE state != 0;",
      "interval": 60
    },
    "installed_applications": {
      "query": "SELECT name, path, bundle_version, minimum_system_version, applescript_enabled, bundle_executable FROM apps;",
      "interval": 60
    },
    "all_kexts": {
      "query": "SELECT name, version FROM kernel_extensions;",
      "interval": 60
    },
    "non_apple_kexts": {
      "query": "SELECT * FROM kernel_extensions WHERE name NOT LIKE 'com.apple.%' AND name != '__kernel__';",
      "interval": 60
    },
    "processes_binding_to_ports": {
      "query": "SELECT DISTINCT process.name, listening.port, listening.protocol, listening.family, listening.address, process.pid, process.path, process.on_disk, process.parent, process.start_time FROM processes AS process JOIN listening_ports AS listening ON process.pid = listening.pid;",
      "interval": 60
    },
    "processes_not_on_disk": {
      "query": "SELECT * FROM processes WHERE on_disk != 1;",
      "interval": 60
    }
  }
}
```

Each query provides useful information and will run every minute. But what sort of impact will this have on the client machines?

For this we can use `./tools/analysis/profile.py` to profile the queries by running them for a configured number of rounds and reporting the pre-defined performance category of each. A higher category result means higher impact. High impact queries should be avoided, but if the information is valuable, consider running them less-often.

```
$ sudo -E python ./tools/analysis/profile.py --config osquery.conf
Profiling query: SELECT * FROM kernel_extensions WHERE name NOT LIKE 'com.apple.%' AND name != '__kernel__';
 D:0  C:0  M:0  F:0  U:1  non_apple_kexts (1/1): duration: 0.519426107407 cpu_time: 0.096729864 memory: 6447104 fds: 5 utilization: 9.5
Profiling query: SELECT name, path, bundle_version, minimum_system_version, applescript_enabled, bundle_executable FROM apps;
 D:0  C:0  M:0  F:0  U:1  installed_applications (1/1): duration: 0.507317066193 cpu_time: 0.113432314 memory: 7639040 fds: 6 utilization: 11.15
Profiling query: SELECT service, process FROM alf_services WHERE state != 0;
 D:0  C:0  M:0  F:0  U:0  alf_services (1/1): duration: 0.525090932846 cpu_time: 0.021108868 memory: 5406720 fds: 5 utilization: 1.9
Profiling query: SELECT * FROM processes WHERE on_disk != 1;
 D:0  C:0  M:0  F:0  U:0  processes_not_on_disk (1/1): duration: 0.521270990372 cpu_time: 0.030440911 memory: 6148096 fds: 5 utilization: 2.8
Profiling query: SELECT name, version FROM kernel_extensions;
 D:0  C:0  M:0  F:0  U:1  all_kexts (1/1): duration: 0.522475004196 cpu_time: 0.089579066 memory: 6500352 fds: 5 utilization: 8.65
Profiling query: SELECT DISTINCT process.name, listening.port, listening.protocol, listening.family, listening.address, process.pid, process.path, process.on_disk, process.parent, process.start_time FROM processes AS process JOIN listening_ports AS listening ON process.pid = listening.pid;
 D:2  C:1  M:0  F:0  U:2  processes_binding_to_ports (1/1): duration: 1.02116107941 cpu_time: 0.668809664 memory: 6340608 fds: 5 utilization: 44.3
```

The results (utilization=2) suggest running `processes_binding_to_ports` less often.

To estimate how often these should run you should evaluate what a differential in the information means from your visibility requirement's perspective (how meaningful is a change vs. how often you check for the change). Then weigh that value against the performance impact of running the query.

Queries that fail to execute (for example, due to a non-existent table) will return the highest category result '3' and the value '-1' for all statistics. 

## Continuous Build

The continuous integration for osquery is currently under development. The previous CI solution was unreliably failing builds due to network and memory issues.

The build will run each of the support operating system platform/versions and include the following phases:

* Build and run `make test`
* Attempt to detect memory leaks using `./tools/analysis/profile.py --leaks`
* Run a performance measurement using `./tools/analysis/profile.py`
* Check performance against the latest release tag and commit to master
* Build docs and API spec on release tag or commit to master

## Virtual table blacklist

Performance impacting virtual tables are most likely the result of missing features/tooling in osquery. Because of their dependencies on core optimizations, there is no harm including the table generation code in master as long as the table is blacklisted when a non-developer builds the tool suite.

If you are developing latent tables that would be blacklisted, please make sure you are relying on a feature with a clear issue and traction. Then add your table name (as it appears in the `.table` spec) to [`specs/blacklist`](https://github.com/facebook/osquery/blob/master/specs/blacklist) and adopt:

```
$ DISABLE_BLACKLIST=1 make
```

For your build iteration.

## Deployment profiling

Before deploying an osquery config use:

```
./tools/analysis/profile.py --config /path/to/osquery.conf --count 1 --rounds 4
```

To estimate the amount of CPU/memory load the system will incur for each query.

## Wishlist

Query implementation isolation options.
