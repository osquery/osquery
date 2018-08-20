A 'universal' Linux package can be created for each package distribution system. These packages contain the osquery daemon, shell, example configuration and startup scripts. Note that the `/etc/init.d/osqueryd` script does not automatically start the daemon until a configuration file is created.

Each osquery tag (stable release) is published to **yum** and **apt** repositories for our supported operating systems: [https://osquery.io/downloads](http://osquery.io/downloads/).

The default packages create the following structure:

```sh
/etc/osquery/
/usr/share/osquery/osquery.example.conf
/usr/share/osquery/lenses/{*}.aug
/usr/share/osquery/packs/{*}.conf
/var/log/osquery/
/usr/lib/osquery/
/usr/bin/osqueryctl
/usr/bin/osqueryd
/usr/bin/osqueryi
```

## Installing osquery

To install osquery follow the instructions on the [Downloads](https://osquery.io/downloads/official) page according to your distro.

## Running osquery

To start a standalone osquery use: `osqueryi`. This does not need a server or service. All the table implementations are included!

After exploring the rest of the documentation you should understand the basics of configuration and logging. These and most other concepts apply to the **osqueryd**, the daemon, tool. To start the daemon:

```
sudo cp /usr/share/osquery/osquery.example.conf /etc/osquery/osquery.conf
# sudo service osqueryd start
sudo systemctl start osqueryd
```

> NOTICE: The interactive shell and daemon do NOT communicate!
