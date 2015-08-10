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
an OS X package installer. You will have to manage and deploy updates.

Each osquery tag (release) builds an OS X package:
[osquery.io/downloads](https://osquery.io/downloads/).
There are no package or library dependencies.

The default package creates the following structure:

```sh
/private/var/osquery/com.facebook.osqueryd.plist
/private/var/osquery/osquery.example.conf
/private/var/log/osquery/
/private/var/osquery/packs/
/usr/local/lib/osquery/
/usr/local/bin/osqueryctl
/usr/local/bin/osqueryd
/usr/local/bin/osqueryi
```

This package does NOT install a LaunchDaemon to start osqueryd. You may use the `osqueryctl` script to install the sample launch daemon script.

## Running osquery

To start a standalone osquery use: `$ osqueryi`. This does not need a server or service. All the table implementations are included!

After exploring the rest of the documentation you should understand the basics of configuration and logging. These and most other concepts apply to the `osqueryd`, the daemon, tool. To start the daemon as a LaunchDaemon:

- `sudo cp /var/osquery/osquery.example.conf /var/osquery/osquery.conf`
- `sudo cp /var/osquery/com.facebook.osqueryd.plist /Library/LaunchDaemons`
- `sudo launchctl load /Library/LaunchDaemons/com.facebook.osqueryd.plist`

Note: The interactive shell and daemon do NOT communicate!