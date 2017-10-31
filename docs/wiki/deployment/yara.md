There are two YARA related tables in osquery, which serve very different purposes. The first table, called `yara_events`, uses osquery's [Events framework](../development/pubsub-framework.md) to monitor for filesystem changes and will execute YARA when a file change event fires. The second table, called **yara**, is an on-demand YARA scanning table.

Both of these tables are considered a beta feature right now.

## YARA Configuration

The configuration for osquery is simple. Here is an example config:

```
{
  // Description of the YARA feature.
  "yara": {
    "signatures": {
      // Each key is an arbitrary group name to give the signatures listed
      "sig_group_1": [ "/Users/wxs/sigs/foo.sig", "/Users/wxs/sigs/bar.sig" ],
      "sig_group_2": [ "/Users/wxs/sigs/baz.sig" ]
    },
    "file_paths": {
      // Each key is a key from file_paths
      // The value is a list of signature groups to run when an event fires
      // These will be watched for and scanned when the event framework
      // fire off an event to yara_events table
      "system_binaries": [ "sig_group_1" ],
      "tmp": [ "sig_group_1", "sig_group_2" ]
    }
  },

  // Paths to watch for filesystem events
  "file_paths": {
    "system_binaries": [ "/usr/bin/%", "/usr/sbin/%" ],
    "tmp": [ "/Users/%/tmp/%%", "/tmp/%" ]
  }
}
```

The first thing to notice is the **file_paths** section, which is used to describe which paths to monitor for changes. Each key is an arbitrary category name and the value is a list of paths. The syntax used is documented on the osquery wildcarding rules described on the [FIM](../deployment/file-integrity-monitoring.md) page. The paths, when expanded out by osquery, are monitored for changes and processed by the [**file_events**](https://osquery.io/schema/#file_events) table.

The second thing to notice is the **yara** section, which contains the configuration to use for YARA within osquery. The **yara** section contains two keys: **signatures** and **file_paths**. The **signatures** key contains a set of arbitrary key names, called "signature groups". The value for each of these groups are the paths to the signature files that will be compiled and stored within osquery. The paths to the signature files can be absolute or relative to ```/etc/osquery/yara/```. The **file_paths** key maps the category name for an event described in the global **file_paths** section to a signature grouping to use when scanning.

For example, when a file in */usr/bin/* and */usr/sbin/* is changed it will be scanned with *sig_group_1*, which consists of *foo.sig* and *bar.sig*. When a file in */Users/%/tmp/* (recursively) is changed it will be scanned with *sig_group_1* and *sig_group_2*, which consists of all three signature files.

# yara_events table

Using the configuration above you can see it in action. While osquery was running I executed `touch /Users/wxs/tmp/foo` in another terminal. Here is the relevant queries to show what happened:

```bash
osquery> SELECT * FROM file_events;
+--------------------+----------+------------+---------+----------------+----------------------------------+------------------------------------------+------------------------------------------------------------------+
| target_path        | category | time       | action  | transaction_id | md5                              | sha1                                     | sha256                                                           |
+--------------------+----------+------------+---------+----------------+----------------------------------+------------------------------------------+------------------------------------------------------------------+
| /Users/wxs/tmp/foo | tmp      | 1430078285 | CREATED | 33859499       | d41d8cd98f00b204e9800998ecf8427e | da39a3ee5e6b4b0d3255bfef95601890afd80709 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
+--------------------+----------+------------+---------+----------------+----------------------------------+------------------------------------------+------------------------------------------------------------------+
osquery> SELECT * FROM yara_events;
+--------------------+----------+------------+---------+----------------+-------------+-------+
| target_path        | category | time       | action  | transaction_id | matches     | count |
+--------------------+----------+------------+---------+----------------+-------------+-------+
| /Users/wxs/tmp/foo | tmp      | 1430078285 | CREATED | 33859499       | always_true | 1     |
+--------------------+----------+------------+---------+----------------+-------------+-------+
osquery>
```

The [**file_events**](https://osquery.io/schema/#file_events) table recorded that a file named */Users/wxs/tmp/foo* was created with the corresponding hashes and a timestamp.

The [**yara_events**](https://osquery.io/schema/#yara_events) table recorded that 1 matching rule (*always_true*) was found when the file was created. In this example every file will always have at least one match because I am using a rule which always evaluates to true. In the next example I'll issue the same command to create a file in a monitored directory but have removed the *always_true* rule from my signature files.

```bash
osquery> SELECT * FROM yara_events;
+--------------------+----------+------------+---------+----------------+-------------+-------+
| target_path        | category | time       | action  | transaction_id | matches     | count |
+--------------------+----------+------------+---------+----------------+-------------+-------+
| /Users/wxs/tmp/foo | tmp      | 1430078285 | CREATED | 33859499       | always_true | 1     |
| /Users/wxs/tmp/foo | tmp      | 1430078524 | CREATED | 33860795       |             | 0     |
+--------------------+----------+------------+---------+----------------+-------------+-------+
osquery>
```

As you can see, even though no matches were found a row is still created and stored.

## On-demand YARA scanning

The [**yara**](https://osquery.io/schema/#yara) table is used for on-demand scanning. With this table you can arbitrarily YARA scan any available file on the filesystem with any available signature files or signature group from the configuration. In order to scan, the table must be given a constraint which says where to scan and what to scan with.

In order to determine where to scan, the table accepts either a *path* or a *pattern* constraint. The *path* constraint must be a full path to a single file. There is no expansion or recursion with this constraint. The *pattern* constraint follows the same wildcard rules mentioned before.

Once the "where" is out of the way, you must specify the "what" part. This is done through either the *sigfile* or *sig_group* constraints. The *sigfile* constraint can be either an absolute path to a signature file on disk or a path relative to */var/osquery/*. The signature file will be compiled only for the execution of this one query and removed afterwards. The *sig_group* constraint must consist of a named signature grouping from your configuration file.

Here are some examples of the **yara** table in action:

```bash
osquery> SE:ECT * FROM yara WHERE path="/bin/ls" AND sig_group="sig_group_1";
+---------+-------------+-------+-------------+---------+---------+
| path    | matches     | count | sig_group   | sigfile | pattern |
+---------+-------------+-------+-------------+---------+---------+
| /bin/ls | always_true | 1     | sig_group_1 |         |         |
+---------+-------------+-------+-------------+---------+---------+
osquery> SELECT * FROM yara WHERE path="/bin/ls" AND sig_group="sig_group_2";
+---------+---------+-------+-------------+---------+---------+
| path    | matches | count | sig_group   | sigfile | pattern |
+---------+---------+-------+-------------+---------+---------+
| /bin/ls |         | 0     | sig_group_2 |         |         |
+---------+---------+-------+-------------+---------+---------+
osquery>
```

As you can see in these examples, I'm scanning the same file with two different signature groups and getting different results.

```bash
osquery> SELECT * FROM yara WHERE pattern="/bin/%sh" AND sig_group="sig_group_1";
+-----------+-------------+-------+-------------+---------+----------+
| path      | matches     | count | sig_group   | sigfile | pattern  |
+-----------+-------------+-------+-------------+---------+----------+
| /bin/bash | always_true | 1     | sig_group_1 |         | /bin/%sh |
| /bin/csh  | always_true | 1     | sig_group_1 |         | /bin/%sh |
| /bin/ksh  | always_true | 1     | sig_group_1 |         | /bin/%sh |
| /bin/sh   | always_true | 1     | sig_group_1 |         | /bin/%sh |
| /bin/tcsh | always_true | 1     | sig_group_1 |         | /bin/%sh |
| /bin/zsh  | always_true | 1     | sig_group_1 |         | /bin/%sh |
+-----------+-------------+-------+-------------+---------+----------+
osquery>
```

The above illustrates using the *pattern* constraint to scan */bin/%sh* with a signature group.

```
osquery> SELECT * FROM yara WHERE pattern="/bin/%sh" AND sigfile="/Users/wxs/sigs/baz.sig";
+-----------+---------+-------+-----------+-------------------------+----------+
| path      | matches | count | sig_group | sigfile                 | pattern  |
+-----------+---------+-------+-----------+-------------------------+----------+
| /bin/bash |         | 0     |           | /Users/wxs/sigs/baz.sig | /bin/%sh |
| /bin/csh  |         | 0     |           | /Users/wxs/sigs/baz.sig | /bin/%sh |
| /bin/ksh  |         | 0     |           | /Users/wxs/sigs/baz.sig | /bin/%sh |
| /bin/sh   |         | 0     |           | /Users/wxs/sigs/baz.sig | /bin/%sh |
| /bin/tcsh |         | 0     |           | /Users/wxs/sigs/baz.sig | /bin/%sh |
| /bin/zsh  |         | 0     |           | /Users/wxs/sigs/baz.sig | /bin/%sh |
+-----------+---------+-------+-----------+-------------------------+----------+
osquery>
```

The above is an example of using an absolute path for *sigfile* combined with *pattern*.
