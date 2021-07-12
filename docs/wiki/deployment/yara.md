# YARA-based scanning with osquery

There are two YARA-related tables in osquery, which serve very different purposes. The first table, called
`yara_events`, uses osquery's [Events framework](../development/pubsub-framework.md) to monitor for filesystem changes
and will execute YARA when a file change event fires. The second table, just called `yara`, is a table for performing an
on-demand YARA scan.

In this document, "signature file" is intended to be synonymous with "YARA rule file" (plain-text files commonly
distributed with a `.yar` or `.yara` filename extension, although any extension is allowed).

## YARA Configuration

The configuration for osquery is simple. Here is an example config, grouping some YARA rule files from the local
filesystem:

```json
{
  // Description of the YARA feature.
  "yara": {
    "signatures": {
      // Each key is an arbitrary group name to give the signatures listed
      "sig_group_1": [ "/Users/wxs/sigs/foo.yar", "/Users/wxs/sigs/bar.yar" ],
      "sig_group_2": [ "/Users/wxs/sigs/baz.yar" ]
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

The first thing to notice is the `file_paths` section, which is used to describe which paths to monitor for changes.
Each key is an arbitrary category name and the value is a list of paths. The syntax used is documented on the osquery
wildcard rules described on the [FIM](../deployment/file-integrity-monitoring.md) page. The paths, when expanded out
by osquery, are monitored for changes and processed by the
[`file_events`](https://osquery.io/schema/current/#file_events) table.

The second thing to notice is the `yara` section, which contains the configuration to use for YARA within osquery. The
`yara` section contains two keys: `signatures` and `file_paths`. The `signatures` key contains a set of arbitrary key
names, called "signature groups." The value for each of these groups are the paths to the signature files that will be
compiled and stored within osquery. The paths to the signature files must be absolute paths (not relative paths). The
`file_paths` key maps the category name for an event described in the global `file_paths` section to a signature
grouping to use when scanning.

For example, when a file in `/usr/bin/` and `/usr/sbin/` is changed it will be scanned with `sig_group_1`, which
consists of `foo.yar` and `bar.yar`. When a file in `/Users/%/tmp/` (recursively) is changed it will be scanned with
`sig_group_1` and `sig_group_2`, which consists of all three signature files.

### Retrieving YARA Rules at Runtime

The default behavior of the `yara` table is to use YARA rules specified in a file on the osquery host. However, it
might be more convenient to manage your YARA rules in one location, and have the `yara` table fetch those rules
at runtime, rather than have to update (and version-manage) a YARA rules file on every individual osquery host. Your
organization may also treat YARA rules as security-sensitive data, and you may not wish to store that data on the
filesystem of every osquery host.

To configure osquery to allow the fetching of YARA rules at runtime, first you must set the `enable_yara_sigurl` flag.

Then, set up your `yara` configuration file with the `signature_urls` section, supplying one or more sources for YARA
rules that will be fetched at runtime:

```json
 "yara": { 
   "signature_urls": { 
     "sig_url_1": "https://raw.githubusercontent.com/Yara-Rules/rules/master/cve_rules/CVE-2010-0805.yar", 
     "sig_url_2": "https://raw.githubusercontent.com/Yara-Rules/rules/master/crypto/crypto_signatures.yar", 
     "sig_url_3": "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_APT3102.yar"
   }
 }
```

These references, here named `sig_url_1`, `sig_url_2`, etc. are then supplied with your `yara` table query to specify
the `sigurl` column. For example:

```sql
osquery> select * from yara where path like '%' and sigurl='sig_url_2';
+-------------------------+--------------+-------+-----------+---------+---------+---------+------+-----------+
| path                    | matches      | count | sig_group | sigfile | sigrule | strings | tags | sigurl    |
+-------------------------+--------------+-------+-----------+---------+---------+---------+------+-----------+
| CMakeCache.txt          | Big_Numbers1 | 1     |           |         |         |         |      | sig_url_2 |
+-------------------------+--------------+-------+-----------+---------+---------+---------+------+-----------+
```

YARA rule strings are omitted from output by default, to prevent disclosure in osquery's results and logs. To include
the YARA rules in the `sigrule` column, set the `enable_yara_string` flag to `true`.

By nature of the design described above, your source URL for YARA rules (`sigurl`) can only be one of the URLs in the
osquery config (in the `signature_urls` section). This is your explicit list of allowed source domains for YARA rules.

#### Notes

- Retrieved YARA rules are retrieved only once and then cached; the cached copy is used until it is stale as specified
 by the HTTP `Last-Modified` header in the server's response.
- The osquery agent always validates the HTTPS server certificate of the server providing the YARA signatures, but
currently has no support for client authentication. YARA rule files must be accessible without authentication.

## Continuous monitoring using the yara_events table

Using the configuration above you can see it in action. While osquery is running, we execute `touch /Users/wxs/tmp/foo`
in another terminal. Here are the relevant queries to show what was detected:

```sql
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

The [`file_events`](https://osquery.io/schema/current/#file_events) table recorded that a file named
`/Users/wxs/tmp/foo` was created with the corresponding hashes and a timestamp.

The [`yara_events`](https://osquery.io/schema/current/#yara_events) table recorded that 1 matching rule (`always_true`)
was found when the file was created. In this example every file will always have at least one match because we are
using a rule which always evaluates to true. In the next example we'll issue the same command to create a file in a
monitored directory but have removed the `always_true` rule from our signature files.

```sql
osquery> SELECT * FROM yara_events;
+--------------------+----------+------------+---------+----------------+-------------+-------+
| target_path        | category | time       | action  | transaction_id | matches     | count |
+--------------------+----------+------------+---------+----------------+-------------+-------+
| /Users/wxs/tmp/foo | tmp      | 1430078285 | CREATED | 33859499       | always_true | 1     |
| /Users/wxs/tmp/foo | tmp      | 1430078524 | CREATED | 33860795       |             | 0     |
+--------------------+----------+------------+---------+----------------+-------------+-------+
```

As you can see, even though no matches were found, a row is still created and stored.

## On-demand YARA scanning

The [`yara`](https://osquery.io/schema/current/#yara) table is used for on-demand scanning. With this table
you can arbitrarily YARA scan any available file on the filesystem with any available signature files or
signature group from the configuration. In order to scan, the table must be given a constraint which says
where to scan and what to scan with.

In order to determine where to scan, the `path` constraint must be a full path to a single file, or a
`path LIKE` with a wildcard pattern. There is no expansion or recursion with this constraint. Note that
you must use `LIKE` if you want to use a wildcard pattern.

Once the `where` is out of the way, you must specify the "what" part. This is done through either the
`sigfile` or `sig_group` constraints. The `sigfile` constraint must be an absolute path to a signature
file on the filesystem, not a elative path. The signature file will be compiled only for the execution
of this one query and removed afterwards. The `sig_group` constraint must consist of a named signature
grouping from your configuration file.

Here are some examples of the `yara` table in action:

```sql
osquery> SELECT * FROM yara WHERE path="/bin/ls" AND sig_group="sig_group_1";
+---------+-------------+-------+-------------+---------+---------+---------+
| path    | matches     | count | sig_group   | sigfile | strings | tags    |
+---------+-------------+-------+-------------+---------+---------+---------+
| /bin/ls | always_true | 1     | sig_group_1 |         |         |         |
+---------+-------------+-------+-------------+---------+---------+---------+

osquery> SELECT * FROM yara WHERE path="/bin/ls" AND sig_group="sig_group_2";
+---------+---------+-------+-------------+---------+---------+---------+
| path    | matches | count | sig_group   | sigfile | strings | tags    |
+---------+---------+-------+-------------+---------+---------+---------+
| /bin/ls |         | 0     | sig_group_2 |         |         |         |
+---------+---------+-------+-------------+---------+---------+---------+
```

As you can see in these examples, we scan the same file with two different signature groups and get different results.

```sql
osquery> SELECT * FROM yara WHERE path LIKE "/bin/%sh" AND sig_group="sig_group_1";
+-----------+-------------+-------+-------------+---------+----------+----------+
| path      | matches     | count | sig_group   | sigfile | strings  | tags     |
+-----------+-------------+-------+-------------+---------+----------+----------+
| /bin/bash | always_true | 1     | sig_group_1 |         |          |          |
| /bin/csh  | always_true | 1     | sig_group_1 |         |          |          |
| /bin/ksh  | always_true | 1     | sig_group_1 |         |          |          |
| /bin/sh   | always_true | 1     | sig_group_1 |         |          |          |
| /bin/tcsh | always_true | 1     | sig_group_1 |         |          |          |
| /bin/zsh  | always_true | 1     | sig_group_1 |         |          |          |
+-----------+-------------+-------+-------------+---------+----------+----------+
```

The above illustrates using the `path LIKE` constraint to scan `/bin/%sh` with a signature group.

```sql
osquery> select * from yara where path LIKE 'C:\tmp\%' and sigfile = "C:\tmp\test.yar.txt";
+------------------------------+-------------+-------+-----------+---------------------+-----------------+------+
| path                         | matches     | count | sig_group | sigfile             | strings         | tags |
+------------------------------+-------------+-------+-----------+---------------------+-----------------+------+
| C:\tmp\New Text Document.txt | TextExample | 1     |           | C:\tmp\test.yar.txt | $text_string:0  |      |
| C:\tmp\test.yar.txt          | TextExample | 1     |           | C:\tmp\test.yar.txt | $text_string:35 |      |
+------------------------------+-------------+-------+-----------+---------------------+-----------------+------+
```

The above is an example of using an absolute path for `sigfile` combined with `path LIKE`. Because the sigfile
contains the string its rule is searching for, it has also returned itself as a result.

**Tip:** you can specify `AND count > 0` in your query to return only positive YARA results.

### Inline YARA rules with sigrule

Above, we documented how to query the `yara` table using YARA signatures specified in a local file or retrieved from a
remote host. YARA rules can also be provided inline with the query, using the hidden column `sigrule` as a constraint.

YARA rules take the form of `'rule rulename { condition: [whatever] }'` and follow the
[standard YARA rule syntax](https://yara.readthedocs.io/en/stable/writingrules.html).

For example:

```sql
osquery> select * from yara where path = '/etc/passwd' and sigrule = 'rule always_true { condition: true }';
```

YARA rules don't have a line-terminating character. To enter a multi-line YARA rule, use newlines. This
even works in `osqueryi`:

```sql
osquery> select * from yara where path LIKE 'C:\tmp\%' and sigrule = 'rule hello_world {
    ...> strings:
    ...> $a = "Hello world"
    ...> condition: $a
    ...> }';
+------------------------------+-------------+-------+-----------+---------+---------+------+
| path                         | matches     | count | sig_group | sigfile | strings | tags |
+------------------------------+-------------+-------+-----------+---------+---------+------+
| C:\tmp\New Text Document.txt | hello_world | 1     |           |         |         |      |
+------------------------------+-------------+-------+-----------+---------+---------+------+
```

**Note:**  when entering a `sigrule` inline, be careful to avoid double-quoting the rule and then also a string
variable within the rule, as the second `"` will terminate the rule and cause a `syntax error`. In the example
above, the `sigrule` string has been single-quoted so the enclosed variable `"Hello world"` can be double-quoted.

Because allowing arbitrary YARA rules would also make it possible to retrieve arbitrary file data in the `strings`
column, as a protection, the `strings` column will default to returning empty unless you also set the hidden flag
`enable_yara_string` to `true` (its default is `false`).

## Troubleshooting

### YARA compile error

Before a YARA scan is performed, the YARA engine compiles the rule(s). An error here indicates there is probably an
issue with the YARA rule(s), but, the first thing to check is whether the same rule can be run with the YARA
command-line utility: `yara64.exe myYaraRule.yar fileToScan.foo`. You will be able to get more helpful messages
about the compile error. If, however, this actually works as intended, then perhaps you've found a bug! Please let
the osquery team know, on Slack or by opening an issue on GitHub.

### Error loading YARA rules: 8

At this time, osquery only supports loading _plaintext_ YARA rules/signatures, which it compiles itself at runtime. If
these rules have already been compiled into their binary form (_e.g._ with the `yarac` CLI tool), osquery will
generate an error trying to load the rules.
