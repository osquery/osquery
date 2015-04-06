## Homebrew

The easiest way to install osquery on OS X is via Homebrew. Check the [Homebrew](http://brew.sh/) homepage for installation instructions. 

Run the following:

```bash
$ brew update
$ brew install osquery
```

To update osquery:

```bash
$ brew update
$ brew upgrade osquery
```

## OS X Package

If you plan to manage an enterprise osquery deployment, the easiest installation method is
an OS X package/installer. You will have to manage/deploy updates.

Each osquery tag (release) builds an OS X package:
[osquery.io/downloads](http://osquery.io/downloads/).
There are no package or library dependencies.

The default package creates the following structure:

```sh
/private/var/osquery/com.facebook.osqueryd.plist
/private/var/osquery/osquery.example.conf
/private/var/log/osquery/
/usr/local/lib/osquery/
/usr/local/bin/osqueryctl
/usr/local/bin/osqueryd
/usr/local/bin/osqueryi
```

This package does NOT install a LaunchDaemon to start osqueryd. You may use the `osqueryctl` script to install the sample launch daemon script.
