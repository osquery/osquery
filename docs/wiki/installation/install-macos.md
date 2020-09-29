# Installing on macOS

Continuous Integration currently tests stable release versions of osquery against macOS 10.14 (see the `vmImage: macos-10.14` line in the [CI configuration](https://github.com/osquery/osquery/blob/master/azure-pipelines.yml). There are no reported issues which block expected core functionality on 10.11 and greater, however 10.9 and previous macOS versions are not supported.

## Package Installation

If you plan to manage an enterprise osquery deployment, the easiest installation method is a macOS package installer. You will have to manage and deploy updates.

Each osquery tag (release) builds a macOS package: [osquery.io/downloads](https://osquery.io/downloads/). There are no package or library dependencies.

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

This package does **not** install a LaunchDaemon to start `osqueryd`. You may use the `osqueryctl start` script to copy the sample launch daemon job plist and associated configuration into place.

### Post installation steps

These steps only apply if this is the first time you have ever installed and run `osqueryd` on this Mac.

After completing the package installation run the following commands. If you are using the Chef recipe to install osquery, then these steps are not necessary: the [recipe](https://osquery.readthedocs.io/en/latest/deployment/configuration/#chef-macos) has this covered.

```sh
# You can use the helper script:
sudo osqueryctl start

# Or, install the example config and launch daemon yourself:
sudo cp /var/osquery/osquery.example.conf /var/osquery/osquery.conf
sudo cp /var/osquery/com.facebook.osqueryd.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/com.facebook.osqueryd.plist
```

### Removing osquery

To remove osquery from a macOS system, run the following commands:

```sh
# Unload and remove com.facebook.osquery.plist launchdaemon
sudo launchctl unload /Library/LaunchDaemons/com.facebook.osqueryd.plist
sudo rm /Library/LaunchDaemons/com.facebook.osqueryd.plist

# Remove files/directories created by osquery installer pkg
sudo rm -rf /private/var/log/osquery
sudo rm -rf /private/var/osquery
sudo rm /usr/local/bin/osquery*

sudo pkgutil --forget com.facebook.osquery
```

## Running osquery

To start a standalone osquery use: `osqueryi`. This does not need a server or service. All the table implementations are included!

After exploring the rest of the documentation you should understand the basics of configuration and logging. These and most other concepts apply to `osqueryd`, the daemon.

> NOTICE: The interactive shell and daemon do **not** communicate!
