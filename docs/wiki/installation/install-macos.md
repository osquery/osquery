# Installing on macOS

Continuous Integration currently tests macOS builds of osquery against macOS 11 (see the `os: [macos-` line in
the `build_macos` section of the [CI
configuration](https://github.com/osquery/osquery/blob/master/.github/workflows/build.yml). All core functionality of
osquery should work on macOS 10.14 or newer, although some tables may read data present only on certain versions of
macOS, as Apple adds new data sources or deprecates others. Versions of macOS 10.13 and older are no longer supported.

## Package Installation

If you plan to manage an enterprise osquery deployment, the easiest installation method is a macOS package installer. You will have to manage and deploy updates.

Each osquery tag (release) builds a macOS package: [osquery.io/downloads](https://osquery.io/downloads/). There are no package or library dependencies.

The default package creates the following structure:

```sh
/private/var/osquery/io.osquery.agent.plist
/private/var/osquery/osquery.example.conf
/private/var/log/osquery/
/private/var/osquery/lenses/{*}.aug
/private/var/osquery/packs/{*}.conf
/opt/osquery/lib/osquery.app
/usr/local/bin/osqueryi -> /opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd
/usr/local/bin/osqueryctl -> /opt/osquery/lib/osquery.app/Contents/Resources/osqueryctl
```

**Note:** With the release of osquery 5.x, osquery is now installed as an app bundle at `/opt/osquery/lib/osquery.app`. The new location for `osqueryd` and `osqueryctl` is inside the app bundle at `/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd` and `/opt/osquery/lib/osquery.app/Contents/Resources/osqueryctl` respectively. Symlinks to `osqueryi` and `osqueryctl` are provided in `/usr/local/bin` for convenience.

This package does **not** install a LaunchDaemon to start `osqueryd`. You may use the `osqueryctl start` script to copy the sample launch daemon job plist and associated configuration into place.

### Note on upgrading from osquery 4.x to 5.x

When upgrading from older versions to newer, osquery itself does not provide a mechanism to stop the service of older version, upgrade osquery, and then restart the service.

### Post installation steps

These steps only apply if this is the first time you have ever installed and run `osqueryd` on this Mac.

After completing the package installation run the following commands. If you are using the Chef recipe to install osquery, then these steps are not necessary: the [recipe](https://osquery.readthedocs.io/en/latest/deployment/configuration/#chef-macos) has this covered.

```sh
# You can use the helper script:
sudo osqueryctl start

# Or, install the example config and launch daemon yourself:
sudo cp /var/osquery/osquery.example.conf /var/osquery/osquery.conf
sudo cp /var/osquery/io.osquery.agent.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/io.osquery.agent.plist
```

### Removing osquery

To remove osquery from a macOS system, run the following commands:

```sh
# Unload and remove io.osquery.agent.plist launchdaemon
sudo launchctl unload /Library/LaunchDaemons/io.osquery.agent.plist
sudo rm /Library/LaunchDaemons/io.osquery.agent.plist

# Remove files/directories created by osquery installer pkg
sudo rm -rf /private/var/log/osquery
sudo rm -rf /private/var/osquery
sudo rm /usr/local/bin/osquery*
sudo rm -rf /opt/osquery

sudo pkgutil --forget io.osquery.agent
```

## Running osquery

To start a standalone osquery use: `osqueryi`. This does not need a server or service. All the table implementations are included!

After exploring the rest of the documentation you should understand the basics of configuration and logging. These and most other concepts apply to `osqueryd`, the daemon.

> NOTICE: The interactive shell and daemon do **not** communicate!
