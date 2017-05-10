Everything in SQL!

It may seem weird at first, but try to think of your operating system a as series of tabular concepts. Each concept becomes a SQL table, like processes, or sockets, the filesystem, a host alias, a running kernel module, etc. There are several informational things like OS version, CPU features, memory details, UEFI platform vendor details-- that are not tabular but rather a body of details with labeled data. We can force-fit this into a table with a single row and many columns or a series of key/value rows. When you want to inspect a concept, you `SELECT` the data and in real-time the associated OS APIs are called.

Now consider event streams, each event is a row, like a new USB device connection, or file attribute modification. These are the same concepts with an 'event-like' twist. We do not inspect event-time data in real-time, but rather buffer the events as they occur and represent that buffer as a table! Concept 'actions' can be represented too, you perform an action and generate tabular data. Consider stating a file, or hashing a blob of data, parsing JSON or reading a SQLite database, traversing a directory or requesting a user's list of installed browser plugins. Actions use primary keys as input and generate rows as output, and are best used when `JOIN`ing.

The world of osquery is centered around SQL, decorating, scheduling, differentials, eventing, targeting, everything is SQL and hopefully as expressive as possible. Please do a deep-dive read into how SQL can power intrusion detection, incident response, process auditing, file integrity monitoring and more within our deployment and development guides.

## SQL as understood by osquery

The osquery SQL language is a superset of SQLite's, please read [SQL as understood by SQLite](https://www.sqlite.org/lang.html) for reference. This is a great starting place if coming from MySQL, PostgreSQL, or MSSQL.

`SELECT` only! All mutation-based verbs exist, like `INSERT`, `UPDATE`, `DELETE`, and `ALTER` but they do not do anything-- except if you're fancy and creating run-time tables or `VIEW`s. ;)

> NOTICE: Several tables, `file` for example, require a predicate for one of the columns, and **will not work without it**. See [Tables with arguments](#tables-with-arguments) for more information.

Before diving into the osquery SQL customizations, please familiarize yourself with the osquery [development shell](../introduction/using-osqueryi.md). This shell is designed for ad-hoc exploration of your OS and SQL query prototyping. Then fire up `osqueryi` as your user or as a superuser and try some of the concepts below.

### Shell help

Within the shell, try: `.help`
```
$ osqueryi
osquery - being built, with love, at Facebook
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

Try `.tables` and `.schema` to list all of the tables and their schema. The schema meta-command takes an argument that helps limit the output to a partial string match.

```
osquery> .schema process
[...]
CREATE TABLE process_memory_map(pid INTEGER, start TEXT, end TEXT, permissions TEXT, offset BIGINT, device TEXT, inode INTEGER, path TEXT, pseudo INTEGER);
CREATE TABLE process_open_files(pid BIGINT, fd BIGINT, path TEXT);
CREATE TABLE process_open_sockets(pid INTEGER, fd BIGINT, socket BIGINT, family INTEGER, protocol INTEGER, local_address TEXT, remote_address TEXT, local_port INTEGER, remote_port INTEGER, path TEXT);
CREATE TABLE processes(pid BIGINT, name TEXT, path TEXT, cmdline TEXT, state TEXT, cwd TEXT, root TEXT, uid BIGINT, gid BIGINT, euid BIGINT, egid BIGINT, suid BIGINT, sgid BIGINT, on_disk INTEGER, wired_size BIGINT, resident_size BIGINT, phys_footprint BIGINT, user_time BIGINT, system_time BIGINT, start_time BIGINT, parent BIGINT, pgroup BIGINT, nice INTEGER);
```

This [complete schema](https://osquery.io/docs/tables/) for all supported platforms is available on the homepage. To see schema in your shell for tables foreign to your OS, like kernel modules on OSX, use the `--enable_foreign` [command line flag](../installation/cli-flags.md).

### Your first query

On OS X (or Linux), select 1 process's pid, name, and path. Then change the display mode and issue the same query:
```
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

To really hammer home the real-time representation try: `SELECT * FROM time;`. Feel free to inspect other concepts/tables, use `.mode line` for the best output within smaller terminal views.

Then let's look at a "meta" table that provides details to osquery about osquery, these tables are prefixed with `osquery_`:
```
osquery> .mode line
osquery> SELECT * FROM osquery_info;
           pid = 3811
       version = 1.7.4
   config_hash =
  config_valid = 0
    extensions = active
build_platform = darwin
  build_distro = 10.11
    start_time = 1464730373
```

This will always show the current PID of the running osquery process, shell or otherwise.

Let's use this to demonstrate `JOIN`ing:
```
osquery> SELECT pid, name, path FROM osquery_info JOIN processes USING (pid);
  pid = 3811
 name = osqueryi
 path = /usr/local/bin/osqueryi
```

Now let's get fancy and complicated, by performing two `JOIN`s and adding a `WHERE` clause:
```
osquery> SELECT p.pid, name, p.path as process_path, pf.path as open_path
    ...>   FROM osquery_info i
    ...>   JOIN processes p ON p.pid = i.pid
    ...>   JOIN process_open_files pf ON pf.pid = p.pid
    ...>   WHERE pf.path LIKE '/dev/%';
         pid = 3811
        name = osqueryi
process_path = /usr/local/bin/osqueryi
   open_path = /dev/ttys000

         pid = 3811
        name = osqueryi
process_path = /usr/local/bin/osqueryi
   open_path = /dev/ttys000

         pid = 3811
        name = osqueryi
process_path = /usr/local/bin/osqueryi
   open_path = /dev/ttys000

         pid = 3811
        name = osqueryi
process_path = /usr/local/bin/osqueryi
   open_path = /dev/null
```

We can expand upon this later using subqueries and more tables.

### Tables with arguments

Several tables, `file` for example, represent concepts that require arguments. Consider `SELECT * FROM file`, you do not want this to trigger a complete walk of the mounted file systems. It is an ambiguous concept without some sort of argument or input parameter. These tables, and their columns, are flagged by a *dropper icon* in the [table documentation](https://osquery.io/docs/tables/) as requiring a column or as using a column to generate additional information.

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

The documentation for [`file`](https://osquery.io/docs/tables/#file) says both `path` and `directory` can be used as input parameters. In *most* cases these columns and tables should "do the right thing" and respond to various operators. String data, like paths, are not easily compared so `=` or `<>` and `LIKE` are the only operators that make sense.

Let's get semi-fancy:
```
osquery> SELECT path, inode, size, type
    ...>   FROM file
    ...>   WHERE path IN (SELECT '/dev/zero');
 path = /dev/zero
inode = 304
 size = 0
 type = character
```

Now let's introduce the [`hash`](https://osquery.io/docs/tables/#hash) table and hopefully show something useful, like the hash of the last file modified in `/etc`:
```
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

**Math functions**

osquery includes the following C-math functions: `sqrt`, `log`, `log10`, `ceil`, `floor`, `power`, `pi`.

The following trig functions: `sin`, `cos`, `tan`, `cot`, `asin`, `acos`, `atan`, and `radians` to `degrees` conversions.

**String functions**

String parsing functions are always helpful, some help within subqueries so they make sense as local-additions:

- `split(COLUMN, TOKENS, INDEX)`: split `COLUMN` using any character token from `TOKENS` and return the `INDEX` result. If an `INDEX` result does not exist, a `NULL` type is returned.
- `regex_split(COLUMN, PATTERN, INDEX)`: similar to split, but instead of `TOKENS`, apply the POSIX regex `PATTERN` (as interpreted by boost::regex).
- `inet_aton(IPv4_STRING)`: return the integer representation of an IPv4 string.

**Hashing functions**

We have added `sha1`, `sha256`, and `md5` functions that take a single argument and return the hashed value.

### Table and column name deprecations

Over time it may makes sense to rename tables and columns. osquery tries to apply plurals to table names and achieve the easiest foreign key JOIN syntax. This often means slightly skewing concept attributes or biasing towards diction used by POSIX.

The tools makes an effort to mark deprecated tables and create 'clone' `VIEW`s so previously scheduled queries continue to work. Similarly for old column names, the column will be marked `HIDDEN` and only returned if explicitly selected. This does not make queries using `*` future-proof, as they will begin using the new column names when the client is updated. All of these changes are considered osquery API changes and marked as such in [release notes](https://github.com/facebook/osquery/releases) on Github.
