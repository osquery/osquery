# Utility Tables

osquery provides several utility tables, which expose various aspects of its internal state and configuration.

## `osquery_events`

This table keeps state about the events subsystem.

```sqlite
CREATE TABLE osquery_events(`name` TEXT, `publisher` TEXT, `type` TEXT, `subscriptions` INTEGER, `events` INTEGER, `refreshes` INTEGER, `active` INTEGER);
```

See the [Process Auditing](process-auditing.md) page for more information.

## `osquery_extensions`

This table contains all extensions that have been loaded.

```sqlite
CREATE TABLE osquery_extensions(`uuid` BIGINT, `name` TEXT, `version` TEXT, `sdk_version` TEXT, `path` TEXT, `type` TEXT);
```

See the [SDK and Extensions](../development/osquery-sdk.md) page for more information.

## `osquery_flags`

This table contains all configuration flags that have been applied.

```sqlite
CREATE TABLE osquery_flags(`name` TEXT, `type` TEXT, `description` TEXT, `default_value` TEXT, `value` TEXT, `shell_only` INTEGER);
```

See the [Process Auditing](process-auditing.md) and [Command Line Flags](../installation/cli-flags.md) pages for more information.

## `osquery_info`

This table contains osquery build information.

```sqlite
CREATE TABLE osquery_info(`pid` INTEGER, `uuid` TEXT, `instance_id` TEXT, `version` TEXT, `config_hash` TEXT, `config_valid` INTEGER, `extensions` TEXT, `build_platform` TEXT, `build_distro` TEXT, `start_time` INTEGER, `watcher` INTEGER, `platform_mask` INTEGER);
```

## `osquery_packs`

This table contains all packs that have been loaded.

```sqlite
CREATE TABLE osquery_packs(`name` TEXT, `platform` TEXT, `version` TEXT, `shard` INTEGER, `discovery_cache_hits` INTEGER, `discovery_executions` INTEGER, `active` INTEGER);
```

See the [Configuration](configuration.md) page for more information.

## `osquery_registry`

This table contains a list of all internal registry items - including tables.

```sqlite
CREATE TABLE osquery_registry(`registry` TEXT, `name` TEXT, `owner_uuid` INTEGER, `internal` INTEGER, `active` INTEGER);
```

To retrieve a list of all available tables, run:

```sqlite
SELECT * FROM osquery_registry WHERE active = true AND internal = false AND registry = 'table';
```

To retrieve all available columns from a table, use:

```sqlite
pragma table_info("table-name");
```

This is the output for the `users` table:

```+-----+-------------+--------+---------+------------+----+
   | cid | name        | type   | notnull | dflt_value | pk |
   +-----+-------------+--------+---------+------------+----+
   | 0   | uid         | BIGINT | 1       |            | 1  |
   | 1   | gid         | BIGINT | 0       |            | 0  |
   | 2   | uid_signed  | BIGINT | 0       |            | 0  |
   | 3   | gid_signed  | BIGINT | 0       |            | 0  |
   | 4   | username    | TEXT   | 1       |            | 2  |
   | 5   | description | TEXT   | 0       |            | 0  |
   | 6   | directory   | TEXT   | 0       |            | 0  |
   | 7   | shell       | TEXT   | 0       |            | 0  |
   | 8   | uuid        | TEXT   | 0       |            | 0  |
   +-----+-------------+--------+---------+------------+----+
```

`pragma` queries can be used to query SQLite internals. For more information, see [the SQLite documentation](https://www.sqlite.org/pragma.html#pragma_table_info).

## `osquery_schedule`

This table contains all scheduled queries, along with information about their execution.

See the [Configuration](configuration.md) page for more information.

```sqlite
CREATE TABLE osquery_schedule(`name` TEXT, `query` TEXT, `interval` INTEGER, `executions` BIGINT, `last_executed` BIGINT, `denylisted` INTEGER, `output_size` BIGINT, `wall_time` BIGINT, `user_time` BIGINT, `system_time` BIGINT, `average_memory` BIGINT, `blacklisted` INTEGER HIDDEN);
```