# Performance safety

High-performance visibility capability is a core feature of osquery. However, user-formed queries are very powerful, and generate opportunities to ruin the performance guarantees of osquery using ill-formed queries.

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

```bash
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

To estimate how often these should run, you should evaluate what a differential in the information means from your visibility requirement perspective (how meaningful is a change vs. how often you check for the change). Then weigh the value of that information against the performance impact of running the query.

### Understanding the output from profile.py

The osquery `profile.py` script uses `utils.py` in `tools/tests/` which uses python’s `psutil` library to collect process stats for osqueryi as its running given queries.

The script returns 5 stats:

**Utilization (U)**: Utilization is calculated by taking the average of non-0 results of the cpu_percent(interval=1) function in `psutils.Process()`. This value can be greater than 100% for processes with threads running across different CPUs. The script sets an interval of 1 meaning that the function compares process time to system CPU times elapsed before and after the 1 second interval. This is a blocking call.

**CPU time (C)**: CPU time uses the `psutils.Process()`'s `cpu_times()` function. It returns a named tuple containing user, system, children_user, system_user, and iowait

- user: time spent in user mode.
- system: time spent in kernel mode.
- children_user: user time of all child processes (always 0 on Windows and macOS).
- system_user: user time of all child processes (always 0 on Windows and macOS).
- iowait: (Linux) time spent waiting for blocking I/O to complete. This value is excluded from user and system times count (because the CPU is not doing any work).

The profile script adds user and system together for the CPU Time output.

**Duration (D)**:
Duration is calculated by taking the subtracting `start_time` - 2 from the current time. The start time is set before the script starts the `osqueryi` process to run the query. The `start_time` - 2 comes from the `--profile_delay` flag used by the profile.py script. This flag causes osquery to wait before and after running the code under test. The 2 is to make up for this wait time.

**fds (F)**: Uses the `num_fds()` function and returns the file descriptors used by the `osqueryi` process during query execution

**Memory (M)**: Uses the `memory_info_ex()` function which is deprecated. psutils documentation suggests using `memory_info()` instead. The function returns a named tuple and the script uses the `rss` value in the tuple. RSS stands for resident set size and is the non-swapped physical memory used by the process. This should match the RES column in `top`.

### Understanding Profile.py Categories

The numbers next to the stats in the script output (categories) are determined by the `RANGES` dictionary in `profile.py`

```python
KB = 1024 * 1024
RANGES = {
    "colors": (utils.blue, utils.green, utils.yellow, utils.red),
    "utilization": (8, 20, 50),
    "cpu_time": (0.4, 1, 10),
    "memory": (8 * KB, 12 * KB, 24 * KB),
    "fds": (10, 20, 50),
    "duration": (0.8, 1, 3),
}
```

The script will take the value of the stat and compare it with the tuple at the corresponding stat's key in `RANGES`. If the value is less than the value in the tuple then the index for the value in the tuple is what appears in the script output. If the value for the stat is greater than all values of the tuple, then the length of the tuple is what appears in the script output. For example, if `cpu_time` for a query is 0.2, then you'll see `C: 0` in the script output. If `cpu_time` is 11, then you'll see `C:3` in the script output.

Queries that fail to execute (for example, due to a non-existent table) will return the highest category result `3` and the value `-1` for all statistics.

## Continuous Build

Each build on the Continuous Integration server will run on each of the supported operating system platform/versions and include the following phases:

- Build and run tests
- Attempt to detect memory leaks using `./tools/analysis/profile.py --leaks`
- Run a performance measurement using `./tools/analysis/profile.py`
- Check performance against the latest release tag and commit to master
- Build docs and API spec on release tag or commit to master

## Virtual table denylist

Performance impacting virtual tables are most likely the result of missing features/tooling in osquery. Because of their dependencies on core optimizations, there is no harm including the table generation code in master as long as the table is denylisted when a non-developer builds the tool suite.

If you are developing latent tables that would be denylisted, please make sure you are relying on a feature with a clear issue and traction. Then add your table name (as it appears in the `.table` spec) to [`specs/denylist`](https://github.com/osquery/osquery/blob/master/specs/denylist) and define the following in your build step:

```bash
DISABLE_DENYLIST=1 make
```

## Deployment profiling

Before deploying an osquery config, use:

```sh
./tools/analysis/profile.py --config /path/to/osquery.conf --count 1 --rounds 4
```

to estimate the amount of CPU/memory load that the system will incur for each query.

## Wishlist

Query implementation isolation options.
