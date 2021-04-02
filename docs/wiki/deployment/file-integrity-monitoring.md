# File Integrity Monitoring with osquery

File integrity monitoring (FIM) is available for Linux (in `file_events`, using the inotify subsystem, and in `process_file_events` using the Audit subsystem), Windows (in `ntfs_journal_events`, using NTFS Journaling) and macOS (in `file_events`, using FSEvents).

## FIM basics in osquery

Collecting file events in osquery requires that you first specify a list of files/directories to monitor from the osquery configuration. The events that relate to those selected files will then populate the corresponding tables on each platform.

FIM is also disabled by default in osquery. To enable it, first ensure that events are enabled in osquery (`--disable_events=false`), then ensure that the desired FIM table is enabled with the corresponding CLI flag (`--enable_file_events=true` for `file_events`, `--disable-audit=false` for `process_file_events`, `--enable_ntfs_publisher=true` for `ntfs_journal_events`).

To specify which files and directories you wish to monitor, you must use *fnmatch*-style, or filesystem globbing, patterns to represent the target paths. You may use standard wildcards `*`/`**` or SQL-style wildcards `*%*`, as shown below.

## Matching wildcard rules

- `%`: Match all files and folders for one level.
- `%%`: Match all files and folders recursively.
- `%abc`: Match all within-level ending in "abc".
- `abc%`: Match all within-level starting with "abc".

## Matching examples

- `/Users/%/Library`: Monitor for changes to every user's Library folder, *but not the contents within*.
- `/Users/%/Library/`: Monitor for changes to files *within* each Library folder, but not the contents of their subdirectories.
- `/Users/%/Library/%`: Same, changes to files within each Library folder.
- `/Users/%/Library/%%`: Monitor changes recursively within each Library.
- `/bin/%sh`: Monitor the `bin` directory for changes ending in `sh`.

**Note:** You cannot match recursively inside a path. For example `/Users/%%/Configuration.conf` is not a valid wildcard.

**Note:** Many applications may *replace* a file instead of editing it in place. If you monitor the file directly, osquery will need to be restarted in order to monitor the replacement. You can avoid this by monitoring the containing *directory* instead.

After you identify the files and directories you wish to monitor, add their match rules to the `file_paths` section in the osquery FIM config.

The three elements of a FIM config in osquery are (a) the scheduled query against `file_events`, (b) the added `file_paths` section, and (c) the `exclude_paths` sections. The `file_events` query is scheduled to collect all of the FIM events that have occurred on any files within the paths specified within `file_paths` but excluding the paths specified within `exclude_paths` on a five minute interval. At a high level, this means events are buffered within osquery and sent to the configured _logger_ every five minutes.

## Example FIM Config

```json
{
  "schedule": {
    "crontab": {
      "query": "SELECT * FROM crontab;",
      "interval": 300
    },
    "file_events": {
      "query": "SELECT * FROM file_events;",
      "removed": false,
      "interval": 300
    }
  },
  "file_paths": {
    "homes": [
      "/root/.ssh/%%",
      "/home/%/.ssh/%%"
    ],
    "etc": [
      "/etc/%%"
    ],
    "tmp": [
      "/tmp/%%"
    ]
  },
  "exclude_paths": {
    "homes": [
      "/home/not_to_monitor/.ssh/%%"
    ],
    "tmp": [
      "/tmp/too_many_events/"
    ]
  }
}
```

Do not use arbitrary category names under the `exclude_paths` node; only valid names are allowed.

- **Valid categories** - Categories referenced under the `file_paths` node. In the above example config, `homes`, `etc` and `tmp` are valid categories.
- **Invalid categories** - Any name not referenced under `file_paths`. In the above example, any name besides `homes`, `etc` and `tmp` is invalid. Invalid categories get dropped silently, i.e., they don't have any effect on the events generated.

In addition to `file_paths`, you can use `file_paths_query` to specify the file paths to monitor as the `path` column of the results of the given query. For example:

```json
{
    "file_paths_query": {
        "category_name": [
            "SELECT DISTINCT '/home/' || username || '/.gitconfig' as path FROM last WHERE username != '' AND username != 'root';"
        ]
    }
}
```

## Sample Event Output

As file changes happen, events will appear in the [**file_events**](https://osquery.io/schema/current/#file_events) table. During a file change event, the md5, sha1, and sha256 for the file will be calculated if possible. A sample event looks like this:

```json
{
  "action":"ATTRIBUTES_MODIFIED",
  "category":"homes",
  "md5":"bf3c734e1e161d739d5bf436572c32bf",
  "sha1":"9773cf934440b7f121344c253a25ae6eac3e3182",
  "sha256":"d0d3bf53d6ae228122136f11414baabcdc3d52a7db9736dd256ad81229c8bfac",
  "target_path":"\/root\/.ssh\/authorized_keys",
  "time":"1429208712",
  "transaction_id":"0"
}
```

## Tuning Linux inotify limits

On Linux, the `file_events` table in osquery uses `inotify` to subscribe to file changes. There are inherently some limitations on the number of files that can be monitored, since each `inotify` watch takes up a certain amount of memory in kernel space (non-swappable memory). Adjusting your limits accordingly can help increase the file limit, at a cost of kernel memory.

### Example sysctl.conf modifications

```text
#/proc/sys/fs/inotify/max_user_watches = 8192
fs.inotify.max_user_watches = 524288

#/proc/sys/fs/inotify/max_user_instances = 128
fs.inotify.max_user_instances = 256

#/proc/sys/fs/inotify/max_queued_events = 16384
fs.inotify.max_queued_events = 32768
```

## File Accesses (Linux only)

In addition to FIM, which generates events if a file is created/modified/deleted, osquery also supports file *access* monitoring which can generate events if a file is accessed.

Monitoring file accesses on Linux uses `inotify` and may incur unexpected and unwanted performance overhead. To prevent 'flooding' of access events alongside FIM, enabling access events for `file_path` categories is an explicit opt-in. You may add categories that were defined in your `file_paths` stanza:

```json
{
  "file_paths": {
    "homes": [
      "/root/.ssh/%%",
      "/home/%/.ssh/%%"
    ],
    "etc": [
      "/etc/%%"
    ],
    "tmp": [
      "/tmp/%%"
    ]
  },
  "file_accesses": ["homes", "etc"]
}
```

The above configuration snippet will enable file integrity monitoring for `homes`, `etc`, and `tmp` but only enable access monitoring for the `homes` and `etc` directories.

> NOTICE: The hashes of files will not be calculated, to avoid generating additional access events.
