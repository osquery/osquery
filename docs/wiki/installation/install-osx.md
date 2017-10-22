Continuous integration currently tests stable release versions of osquery against macOS 10.12 (as listed under the _Build_status_ column on the project [README](https://github.com/facebook/osquery/blob/master/README.md)). There are no reported issues which block expected core functionality on 10.11, however 10.9 and previous macOS versions do not work.

## Package Installation

If you plan to manage an enterprise osquery deployment, the easiest installation method is a macOS package installer. You will have to manage and deploy updates.

Each osquery tag (release) builds a macOS package:
[osquery.io/downloads](https://osquery.io/downloads/). There are no package or library dependencies.

The default package creates the following structure:

```sh
/private/var/osquery/com.facebook.osqueryd.plist
/private/var/osquery/osquery.example.conf
/private/var/log/osquery/
/private/var/osquery/lenses/{*}.aug
/private/var/osquery/packs/{*}.conf
/usr/local/lib/osquery/
/usr/local/bin/osqueryctl
/usr/local/bin/osqueryd
/usr/local/bin/osqueryi
```

This package does NOT install a LaunchDaemon to start **osqueryd**. You may use the `osqueryctl start` script to copy the sample launch daemon job plist and associated configuration into place.

### Post installation steps

Only applies if you have never installed and run **osqueryd** on this Mac.

After completing the brew installation run the following commands. If you are using the chef recipe to install osquery then these steps are not necessary, the [recipe](http://osquery.readthedocs.io/en/stable/deployment/configuration/#chef-os-x) has this covered.

```
sudo ln -s /usr/local/share/osquery /var/osquery
sudo mkdir /var/log/osquery
sudo chown root /usr/local/Cellar/osquery/1.7.3/bin/osqueryd
sudo cp /var/osquery/osquery.example.conf /var/osquery/osquery.conf
```

### Removing osquery
To remove osquery from a macOS system, run the following commands:
```sh
# Unload and remove com.facebook.osquery.plist launchdaemon
launchctl unload /Library/LaunchDaemons/com.facebook.osqueryd.plist
rm /Library/LaunchDaemons/com.facebook.osqueryd.plist

# Remove files/directories created by osquery installer pkg
rm -rf /private/var/log/osquery
rm -rf /private/var/osquery
rm /usr/local/bin/osquery*
```

## Running osquery

To start a standalone osquery use: `osqueryi`. This does not need a server or service. All the table implementations are included!

After exploring the rest of the documentation you should understand the basics of configuration and logging. These and most other concepts apply to **osqueryd**, the daemon, tool. To start the daemon as a LaunchDaemon:

```
$ sudo cp /var/osquery/osquery.example.conf /var/osquery/osquery.conf
$ sudo cp /var/osquery/com.facebook.osqueryd.plist /Library/LaunchDaemons/
$ sudo launchctl load /Library/LaunchDaemons/com.facebook.osqueryd.plist
```

> NOTICE: The interactive shell and daemon do NOT communicate!
