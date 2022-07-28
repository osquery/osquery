# Everything in SQL

It may seem weird at first, but try to think of your operating system as a series of tabular concepts. Each concept becomes a SQL table, like processes, or sockets, the filesystem, a host alias, a running kernel module, etc. There are several informational things — like OS version, CPU features, memory details, UEFI platform vendor details — that are not tabular but rather a body of details with labeled data. We can represent this type of data as a table with a single row and many columns, or a series of key/value rows. When you want to inspect a concept, you `SELECT` the data, and the associated OS APIs are called in real-time.

Now consider event streams: each event is a row, like a new USB device connection, or file attribute modification. These are the same concepts with an 'event-like' twist. We do not inspect event-time data in real-time, but rather buffer the events as they occur and represent that buffer as a table! Concept 'actions' can be represented too, you perform an action and generate tabular data. Consider `stat`-ing a file, hashing a blob of data, parsing JSON, reading a SQLite database, traversing a directory, or requesting a user's list of installed browser plugins. Actions use primary keys as input and generate rows as output, and are best used when `JOIN`ing.

The world of osquery is centered around SQL: decorating, scheduling, differentials, eventing, targeting. Everything is SQL, and hopefully as expressive as possible. Continue reading our deployment and development guides for a deep-dive into how SQL can power intrusion detection, incident response, process auditing, file integrity monitoring and more.

## SQL as understood by osquery

The osquery SQL language is a superset of SQLite's. Please read [SQL as understood by SQLite](https://www.sqlite.org/lang.html) for reference. This is a great starting place if coming from MySQL, PostgreSQL, or MSSQL.

`SELECT` only! All mutation-based verbs exist, like `INSERT`, `UPDATE`, `DELETE`, and `ALTER`, but they do nothing -- unless you're fancy and creating run-time tables or `VIEW`s, or using an extension. Mutation-based verbs are allowed in extensions, if the extension supports them.

> NOTICE: Several tables, `file` for example, require a predicate for one of the columns, and **will not work without it**. See [Tables with arguments](#tables-with-arguments) for more information.

Before diving into osquery's specific implementation of SQL, please familiarize yourself with the osquery [development shell](../introduction/using-osqueryi.md). This shell is designed for ad-hoc exploration of your OS and SQL query prototyping. Then, fire up `osqueryi` as your user or as a superuser, and try some of the concepts below. Know that this 'shell' does not connect to a remote server; it is completely standalone.

### Shell help

Within the shell, try: `.help`

```text
$ osqueryi
Using a virtual database. Need help, type '.help'
osquery> .help
Welcome to the osquery shell. Please explore your OS!
You are connected to a transient 'in-memory' virtual database.

.all [TABLE]       Select all from a table
.bail ON|OFF       Stop after hitting an error; default OFF
.echo ON|OFF       Turn command echo on or off
[...]
osquery>
```

Try the meta-commands `.tables` and `.schema` to list all of the tables and their schema. The `schema` meta-command takes an argument that helps limit the output to a partial string match.

```text
osquery> .schema process
[...]
CREATE TABLE process_memory_map(pid INTEGER, start TEXT, end TEXT, permissions TEXT, offset BIGINT, device TEXT, inode INTEGER, path TEXT, pseudo INTEGER);
CREATE TABLE process_open_files(pid BIGINT, fd BIGINT, path TEXT);
CREATE TABLE process_open_sockets(pid INTEGER, fd BIGINT, socket BIGINT, family INTEGER, protocol INTEGER, local_address TEXT, remote_address TEXT, local_port INTEGER, remote_port INTEGER, path TEXT);
CREATE TABLE processes(pid BIGINT, name TEXT, path TEXT, cmdline TEXT, state TEXT, cwd TEXT, root TEXT, uid BIGINT, gid BIGINT, euid BIGINT, egid BIGINT, suid BIGINT, sgid BIGINT, on_disk INTEGER, wired_size BIGINT, resident_size BIGINT, phys_footprint BIGINT, user_time BIGINT, system_time BIGINT, start_time BIGINT, parent BIGINT, pgroup BIGINT, nice INTEGER);
```

This [complete schema](https://osquery.io/schema/) for all supported platforms is available on the homepage. To see schema in your shell for tables foreign to your OS, like kernel modules on macOS, use the `--enable_foreign` [command line flag](../installation/cli-flags.md).

### Your first query

On macOS (or Linux), select 1 process's pid, name, and path. Then change the display mode and issue the same query:

```text
osquery> SELECT pid, name, path FROM processes LIMIT 1;
+-----+---------+---------------+
| pid | name    | path          |
+-----+---------+---------------+
| 1   | launchd | /sbin/launchd |
+-----+---------+---------------+
osquery> .mode line
osquery> SELECT pid, name, path FROM processes LIMIT 1;
  pid = 1
 name = launchd
 path = /sbin/launchd
osquery> .mode pretty
```

Then try: `SELECT pid, name, path FROM processes ORDER BY start_time DESC LIMIT 1;` several times and you will continue to select the last-most-recent process to start. This data is equivalent to `ps` and is a real-time representation of processes.

To really hammer home the real-time representation, try `SELECT * FROM time;`. Feel free to inspect other concepts/tables. Use `.mode line` for the best output within smaller terminal views.

Then, let's look at a "meta" table that provides details to osquery about itself. These tables are prefixed with `osquery_`:

```text
osquery> .mode line
osquery> SELECT * FROM osquery_info;
           pid = 15982
          uuid = 4892E1C6-F800-5F8E-92B1-BC2216C29D4F
   instance_id = 94c004b0-49e5-4ece-93e6-96c1939c0f83
       version = 2.4.6
   config_hash =
  config_valid = 0
    extensions = active
build_platform = darwin
  build_distro = 10.12
    start_time = 1496552549
       watcher = -1
```

This will always show the current PID of the running osquery process, shell or otherwise.

Let's use this to demonstrate `JOIN`ing:

```text
osquery> SELECT pid, name, path FROM osquery_info JOIN processes USING (pid);
  pid = 15982
 name = osqueryi
 path = /usr/local/bin/osqueryi
```

Now let's get fancy and complicated, by performing two `JOIN`s and adding a `WHERE` clause:

```text
osquery> SELECT p.pid, name, p.path as process_path, pf.path as open_path
    ...>   FROM osquery_info i
    ...>   JOIN processes p ON p.pid = i.pid
    ...>   JOIN process_open_files pf ON pf.pid = p.pid
    ...>   WHERE pf.path LIKE '/dev/%';
         pid = 15982
        name = osqueryi
process_path = /usr/local/bin/osqueryi
   open_path = /dev/ttys000

         pid = 15982
        name = osqueryi
process_path = /usr/local/bin/osqueryi
   open_path = /dev/ttys000

         pid = 15982
        name = osqueryi
process_path = /usr/local/bin/osqueryi
   open_path = /dev/ttys000

         pid = 15982
        name = osqueryi
process_path = /usr/local/bin/osqueryi
   open_path = /dev/null
```

We can expand upon this later using subqueries and more tables.

### Tables with arguments

Several tables, `file` for example, represent concepts that require arguments. Consider `SELECT * FROM file`: you do not want this to trigger a complete walk of the mounted file systems. It is an ambiguous concept without some sort of argument or input parameter. These tables, and their columns, are flagged by a *dropper icon* in the [schema documentation](https://osquery.io/schema/) as requiring a column or as using a column to generate additional information.

Let's exercise the `file` table:

```
osquery> .mode line
osquery> SELECT * FROM file;
osquery> SELECT * FROM file WHERE path = '/dev/zero';
      path = /dev/zero
 directory = /dev
  filename = zero
     inode = 304
       uid = 0
       gid = 0
      mode = 0666
    device = 50331651
      size = 0
block_size = 131072
     atime = 1463786341
     mtime = 1463786341
     ctime = 1463786341
     btime = 0
hard_links = 1
      type = character
osquery> SELECT count(1) FROM file WHERE path LIKE '/dev/%';
count(1) = 568
```

The documentation for [`file`](https://osquery.io/schema/current/#file) says both `path` and `directory` can be used as input parameters. In *most* cases these columns and tables should "do the right thing" and respond to various operators. String data, like paths, are not easily compared so `=` or `<>` and `LIKE` are the only operators that make sense.

Let's get semi-fancy:

```
osquery> .mode line
osquery> SELECT path, inode, size, type
    ...>   FROM file
    ...>   WHERE path IN (SELECT '/dev/zero');
 path = /dev/zero
inode = 304
 size = 0
 type = character
```

Now let's introduce the [`hash`](https://osquery.io/schema/current/#hash) table and hopefully show something useful, like the hash of the last file modified in `/etc`:

```
osquery> .mode line
osquery> SELECT path, mtime, sha256
    ...>   FROM file
    ...>   JOIN hash USING (path)
    ...>   WHERE file.directory = '/etc'
    ...>   ORDER BY mtime DESC LIMIT 1;
  path = /etc/krb5.keytab
 mtime = 1464730624
sha256 = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### SQL additions

osquery includes various 'additional' SQL functions and aggregations. We try to balance SQL feature requests using a locality question: "does this make sense to execute on a single host, or many?" If the aggregation or function would be better suited with information from a fleet or group of hosts, find a mechanism to perform the function/aggregation after-the-fact.

#### Math functions

osquery includes the following C-math functions: `sqrt`, `log`, `log10`, `ceil`, `floor`, `power`, `pi`.
<details>
<summary>C-Math function examples:</summary>
<p>

    osquery> .mode line

    osquery> select disk_size as disk_size from disk_info;
    disk_size = 107372805120

    osquery> select sqrt(disk_size) as disk_size from disk_info;
    disk_size = 327677.898430761

    osquery> select log(disk_size) as disk_size from disk_info;
    disk_size = 25.3995727757846

    osquery> select log10(disk_size) as disk_size from disk_info;
    disk_size = 11.0308942992233

    osquery> select ceil(disk_size) as disk_size from disk_info;
    disk_size = 107372805120

    osquery> select floor(disk_size) as disk_size from disk_info;
    disk_size = 107372805120

    osquery> select power(disk_size) as disk_size from disk_info;
    disk_size = 1.15289192793375e+22

    osquery> select pi() * disk_size as disk_size from disk_info;
    disk_size = 337321615760.32

</p>
</details>


The following trig functions: `sin`, `cos`, `tan`, `cot`, `asin`, `acos`, `atan`, and `radians` to `degrees` conversions.
<details>
<summary>Trig functions examples:</summary>
<p>

    osquery .mode line

    osquery> select sin(30);
    sin(30) = -0.988031624092862

    osquery> select cos(30);
    cos(30) = 0.154251449887584

    osquery> select tan(30);
    tan(30) = -6.40533119664628

    osquery> select cot(30);
    cot(30) = -0.156119952161659

    osquery> select asin(.5);
    asin(.5) = 0.523598775598299

    osquery> select acos(.5);
    acos(.5) = 1.0471975511966

    osquery> select atan(.5);
    atan(.5) = 0.463647609000806

    osquery> select radians(60);
    radians(60) = 1.0471975511966

    osquery> select degrees(1.3);
    degrees(1.3) = 74.484513367007

</p>
</details>

#### String functions


- `concat(ARG1, ARG2, ARG3...)`: Concatenate arguments, ignoring nulls.

    <details>
    <summary>Concat function example:</summary>
    <p>

      osquery> .mode line

      osquery> select concat('hello', NULL, ' ', 'world');
      concat('hello', NULL, ' ', 'world') = hello world
    </p>
    </details>


- `concat_ws(SEPARATOR, ARG1, ARG2, ARG3...)`: Concatenate arguments, ignoring nulls, and interleaved with `SEPARATOR`.

    <details>
    <summary>Concat_ws function example:</summary>
    <p>

      osquery> .mode line

      osquery> select concat_ws(' ', 'hello', NULL, 'world');
      concat_ws(' ', 'hello', NULL, 'world') = hello world
    </p>
    </details>

- `split(COLUMN, TOKENS, INDEX)`: split `COLUMN` using any character token from `TOKENS` and return the `INDEX` result. If an `INDEX` result does not exist, a `NULL` type is returned.

    <details>
    <summary>Split function example:</summary>
    <p>

      osquery> .mode line

      osquery> select uid from users;
      uid = 500

      uid = 1001

      osquery> select split(uid, 1, 0) from users;
      split(uid, 1, 0) = 500

      split(uid, 1, 0) = 00

    </p>
    </details>

- `regex_split(COLUMN, PATTERN, INDEX)`: similar to split, but instead of `TOKENS`, apply the POSIX regex `PATTERN` (as interpreted by std::regex).

    <details>
    <summary>Regex Split function example:</summary>
    <p>

      osquery> .mode line

      osquery> select uid from users;
      uid = 500

      uid = 1001

      osquery> select split(uid, ("[1-5]"), 0) from users;
      split(uid, 1, 0) = 00

      split(uid, 1, 0) = 00

    </p>
    </details>

- `regex_match(COLUMN, PATTERN, INDEX)`: Runs regex match across the column, and returns matched subgroups. (The 0 index is the full match, subsequent numbers are the groups).

    <details>
    <summary>Regex Match function example:</summary>
    <p>

      osquery> .mode line

      osquery> select regex_match('hello world. Goodbye', '(\w+) \w+', 0) as m0,
	                  regex_match('hello world. Goodbye', '(\w+) \w+', 1) as m1;
      m0 = hello world
      m1 = hello
    </p>
    </details>


- `inet_aton(IPv4_STRING)`: return the integer representation of an IPv4 string.

    <details>
    <summary>IPv4 Int representation example:</summary>
    <p>

      osquery> .mode line

      osquery> select inet_aton("1.0.1.5") as ipInt
      ipInt = 16777477

    </p>
    </details>

#### Hashing functions

We have added `sha1`, `sha256`, and `md5` functions that take a single argument and return the hashed value.
<details>
<summary>Hashing functions example:</summary>
<p>

    osquery> .mode line

    osquery> select username from users;
    username = Guest

    username = System

    osquery> select sha1(username) as usernameHash from users;
    usernameHash = face83ee3014bdc8f98203cc94e2e89222452e90

    usernameHash = 29d43743c43bda9873fc7a79c99f2ec4b6b442b1

    osquery> select sha256(username) as usernameHash from users;
    usernameHash = a835887ac13e6558ea6cb404aae6a35b7cbff6796af813d72f7b8d08f3fa0ec9

    usernameHash = 4d2c882abd33183be08ec6f4b47a1f09d3dd211de7556d9b587f7e34eec5ed0b

    osquery> select md5(username) as usernameHash from users;
    usernameHash = 7d4ef62de50874a4db33e6da3ff79f75

    usernameHash = 2a44946d16fe86e63a7e078744c58d56

</p>
</details>

- `community_id_v1(SOURCE_ADDR, DEST_ADDR, SOURCE_PORT, DEST_PORT, PROTOCOL, SEED)`: returns the [Community ID v1 hash](https://github.com/corelight/community-id-spec) of the network connection. This can be used to match with the Community ID generated by other tools such as Zeek and Suricata. `SEED` is optional and will be set to `0` if omitted. If some values are missing or cannot be parsed, the function will return an empty result and log a warning. For strict error checking (resulting in failure of the query), use `community_id_v1_strict`.

    <details>
    <summary>Community ID v1 Example:</summary>
    <p>

      osquery> .mode line

      osquery> select community_id_v1('66.35.250.204', '128.232.110.120', 80, 34855, 6) AS community_id;
      community_id = 1:LQU9qZlK+B5F3KDmev6m5PMibrg=
      osquery> select community_id_v1('66.35.250.204', '2001:0:3238:DFE1:63::FEFB', 80, 2347, 6) AS community_id;
      community_id = 1:rxU6O+b2d9kbSWjRmVDoBbowx6g=
      osquery> select community_id_v1('66.35.250.204', '2001:0:3238:DFE1:63::FEFB', 80, 2347, 6, 37) AS community_id_with_seed;
      community_id_with_seed = 1:jmJ2ORP31di4mtsQPIKzyoEb3yo=
      osquery> select community_id_v1(local_address,remote_address,local_port,remote_port,protocol) as community_id from process_open_sockets limit 2;
      community_id = 1:PaAbtXl8lgQoYFUShUQwXpcNVfw=
      W0129 10:34:47.759569 195012032 sqlite_hashing.cpp:226] Community ID saddr cannot be parsed as IP

      community_id =

    </p>
    </details>

#### Encoding functions

There are also encoding functions available, to process query results.

- `to_base64`: base64 encode a string.
    <details>
    <summary>Base64 encode example:</summary>
    <p>

      osquery> .mode line

      osquery> select device_id from cpu_info;
      device_id = CPU0

      osquery> select to_base64(device_id) as device_id from cpu_info;
      device_id = Q1BVMA==

    </p>
    </details>
- `from_base64`: Decode a base64 encoded string. If the string is not valid base64 an empty string is returned.
    <details>
    <summary>Base64 decode example:</summary>
    <p>

      osquery> .mode line

      osquery> select device_id from cpu_info;
      device_id = CPU0

      osquery> select to_base64(device_id) as device_id from cpu_info;
      device_id = Q1BVMA==

      select from_base64(to_base64(device_id)) as device_id from cpu_info;
      device_id = CPU0

    </p>
    </details>
- `conditional_to_base64`: Encode a string if and only if the string contains non-ASCII characters.
    <details>
    <summary>Conditional Base64 encode example:</summary>
    <p>

      osquery> .mode line

      osquery> select device_id from cpu_info;
      device_id = CPU0

      osquery> select conditional_to_base64(device_id) as device_id from cpu_info;
      device_id = CPU0

      osquery> select conditional_to_base64(device_id + char(183)) as device_id from cpu_info;
      device_id = 0

    </p>
    </details>

#### Network functions

- `in_cidr_block(CIDR_RANGE, IP_ADDRESS)`: return 1 if the IP address is within the CIDR block, otherwise 0.

    <details>
    <summary>in_cidr_block function example:</summary>
    <p>

      osquery> .mode line

      osquery> SELECT in_cidr_block('10.0.0.0/26', '10.0.0.24');
      in_cidr_block('10.0.0.0/26', '10.0.0.24') = 1

      osquery> SELECT in_cidr_block('2001:db8::/48', '2001:db8:0:ffff:ffff:ffff:ffff:ffff');
      in_cidr_block('2001:db8::/48', '2001:db8:0:ffff:ffff:ffff:ffff:ffff') = 1

    </p>
    </details>

### Table and column name deprecations

Over time it may make sense to rename tables and columns. osquery tries to apply plurals to table names and achieve the easiest foreign key JOIN syntax. This often means slightly skewing concept attributes or biasing towards diction used by POSIX.

osquery makes an effort to mark deprecated tables and create 'clone' `VIEW`s so that previously scheduled queries continue to work. Similarly, for old column names, the column will be marked `HIDDEN` and only returned if explicitly selected. This does not make queries using `*` future-proof, as they will begin using the new column names when the client is updated. All of these changes are considered osquery API changes and marked as such in [release notes](https://github.com/osquery/osquery/releases) on GitHub.
