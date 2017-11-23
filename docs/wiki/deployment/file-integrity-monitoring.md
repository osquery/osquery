File integrity monitoring (FIM) is available for Linux and Darwin using inotify and FSEvents. The daemon reads a list of files/directories from the osquery configuration. The actions (and hashes when appropriate) to those selected files populate the [`file_events`](https://osquery.io/schema/#file_events) table.

To get started with FIM, you must first identify which files and directories you wish to monitor. Then use *fnmatch*-style, or filesystem globbing, patterns to represent the target paths. You may use standard wildcards "*\**" or SQL-style wildcards "*%*":

**Matching wildcard rules**

* `%`: Match all files and folders for one level.
* `%%`: Match all files and folders recursively.
* `%abc`: Match all within-level ending in "abc".
* `abc%`: Match all within-level starting with "abc".

**Matching examples**

* `/Users/%/Library`: Monitor for changes to every user's Library folder.
* `/Users/%/Library/`: Monitor for changes to files within each Library folder.
* `/Users/%/Library/%`: Same, changes to files within each Library folder.
* `/Users/%/Library/%%`: Monitor changes recursively within each Library.
* `/bin/%sh`: Monitor the *bin* directory for changes ending in *sh*.

For example, you may want to monitor `/etc` along with other files on a Linux system. After you identify your target files and directories you wish to monitor, add them to a new section in the config *file_paths*.

The three areas below that are relevant to FIM are the scheduled query against `file_events`, the added `file_paths` section and the `exclude_paths` sections. The `file_events` query is scheduled to collect all of the FIM events that have occurred on any files within the paths specified within `file_paths` but excluding the paths specified within `exclude_paths` on a five minute interval. At a high level this means events are buffered within osquery and sent to the configured _logger_ every five minutes.

**Note:** You cannot match recursively inside a path. For example `/Users/%%/Configuration.conf` is not a valid wildcard.

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

One must not mention arbitrary category name under the exclude_paths node, only valid categories are allowed.

* `valid category` - Categories which are mentioned under `file_paths` node. In the above example config `homes`, `etc` and `tmp` are termed as valid categories.
* `invalid category` - Any other category name apart from `homes`, `etc` and `tmp` are considered as invalid categories.

**Note:** Invalid categories get dropped silently, i.e. they don't have any effect on the events generated.

## Sample Event Output

As file changes happen, events will appear in the [**file_events**](https://osquery.io/schema/#file_events) table.  During a file change event, the md5, sha1, and sha256 for the file will be calculated if possible. A sample event looks like this:

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

For Linux, osquery uses inotify to subscribe to file changes at the kernel level for performance.  This introduces some limitations on the number of files that can be monitored since each inotify watch takes up memory in kernel space (non-swappable memory).  Adjusting your limits accordingly can help increase the file limit at a cost of kernel memory.

### Example sysctl.conf modifications

```
#/proc/sys/fs/inotify/max_user_watches = 8192
fs.inotify.max_user_watches = 524288

#/proc/sys/fs/inotify/max_user_instances = 128
fs.inotify.max_user_instances = 256

#/proc/sys/fs/inotify/max_queued_events = 16384
fs.inotify.max_queued_events = 32768
```

## File Accesses

In addition to FIM which generates events if a file is created/modified/deleted, osquery also supports file access monitoring which can generate events if a file is accessed.

File accesses on Linux using inotify may induce unexpected and unwanted performance reduction. To prevent 'flooding' of access events alongside FIM, enabling access events for `file_path` categories is an explicit opt-in. You may add categories that were defined in your `file_paths` stanza:

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

The above configuration snippet will enable file integrity monitoring for 'homes', 'etc', and 'tmp' but only enable access monitoring for the 'homes' and 'etc' directories.

> NOTICE: The hashes of files will not be calculated to avoid generating additional access events.

### Process File Accesses on macOS

It is possible to monitor for file accesses by process using the osquery macOS kernel module. File accesses induce a LOT of stress on the system and are more or less useless giving the context from userland monitoring systems (aka, not having the process that caused the modification).

If the macOS kernel extension is running, the `process_file_events` table will be populated using the same **file_paths** key in the osquery config. This implementation of access monitoring includes process PIDs and should not cause CPU or memory latency outside of the normal kernel extension/module guarantees. See [../development/kernel.md](Kernel) for more information.
