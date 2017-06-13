A 'universal' Linux package can be created for each package distribution system. These packages contain the osquery daemon, shell, example configuration and startup scripts. Note that the `/etc/init.d/osqueryd` script does not automatically start the daemon until a configuration file is created*.

Each osquery tag (stable release) is published to **yum** and **apt** repositories for our supported operating systems: [https://osquery.io/downloads](http://osquery.io/downloads/).

The default packages create the following structure:

```sh
/etc/osquery/
/usr/share/osquery/osquery.example.conf
/usr/share/osquery/packs/{*}.conf
/var/log/osquery/
/usr/lib/osquery/
/usr/bin/osqueryctl
/usr/bin/osqueryd
/usr/bin/osqueryi
```

## yum-based Distros

You may install the "auto-repo-add" RPM or add the repository target. These RPMs should work on any x86-64 Linux with a base install from 2011 forward:

```sh
$ sudo rpm -ivh https://osquery-packages.s3.amazonaws.com/centos7/noarch/osquery-s3-centos7-repo-1-0.0.noarch.rpm
$ sudo yum install osquery
```

## dpkg-based Distros

Similar to the **yum-based** distributions, the **dpkg-based** DEB packages should work on any x86-64 Linux since 2011:

```sh
$ sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
$ sudo add-apt-repository "deb [arch=amd64] https://osquery-packages.s3.amazonaws.com/xenial xenial main"
$ sudo apt-get update
$ sudo apt-get install osquery
```

\* You may also set a different config plugin using a [**flagfile**](../installation/cli-flags.md).<br />

## Running osquery

To start a standalone osquery use: `osqueryi`. This does not need a server or service. All the table implementations are included!

After exploring the rest of the documentation you should understand the basics of configuration and logging. These and most other concepts apply to the **osqueryd**, the daemon, tool. To start the daemon:

```
sudo cp /usr/share/osquery/osquery.example.conf /etc/osquery/osquery.conf
# sudo service osqueryd start
sudo systemctl start osqueryd
```

> NOTICE: The interactive shell and daemon do NOT communicate!
