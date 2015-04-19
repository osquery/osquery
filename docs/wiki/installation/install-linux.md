## Downloads

Distro-specific packages are built for each supported operating system.
These packages contain the osquery daemon, shell, and example configuration and startup scripts.
This means a `/etc/init.d/osqueryd` script that does not automatically start until a configuration file is created*.

Supported distributions are:

- Ubuntu Trusty 14.04 LTS
- Ubuntu Precise 12.04 LTS
- CentOS 6.5
- CentOS 7

Each osquery tag (release) is published to yum and apt repositories for our supported operating systems: [osquery.io/downloads](http://osquery.io/downloads/).

The default packages create the following structure:

```sh
/etc/osquery/
/var/osquery/osquery.example.conf
/var/log/osquery/
/usr/lib/osquery/
/usr/bin/osqueryctl
/usr/bin/osqueryd
/usr/bin/osqueryi
```

## yum-based Distros

We publish two packages, osquery and osquery-unstable**, in a yum repository for CentOS/RHEL 6.3-6.6 and 7.0 built from our Jenkins build hosts. You may install the "auto-repo-add" RPM or add the repository target:

**CentOS/RHEL 7.0**

```sh
$ sudo rpm -ivh https://osquery-packages.s3.amazonaws.com/centos7/noarch/osquery-s3-centos7-repo-1-0.0.noarch.rpm
$ sudo yum install osquery
```

**CentOS/RHEL 6.6**

```sh
$ sudo rpm -ivh https://osquery-packages.s3.amazonaws.com/centos6/noarch/osquery-s3-centos6-repo-1-0.0.noarch.rpm
$ sudo yum install osquery
```

## dpkg-based Distros

We publish that same two packages, osquery and osquery-unstable, in an apt repository for Ubuntu 12.04 (precise) and 14.04 (trusty):

**Ubuntu Trusty 14.04 LTS**

```sh
$ sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C9D8B80B
$ sudo add-apt-repository "deb [arch=amd64] https://osquery-packages.s3.amazonaws.com/trusty trusty main"
$ sudo apt-get update
$ sudo apt-get install osquery
```

**Ubuntu Precise 12.04 LTS**

```sh
$ sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C9D8B80B
$ sudo add-apt-repository "deb [arch=amd64] https://osquery-packages.s3.amazonaws.com/precise precise main"
$ sudo apt-get update
$ sudo apt-get install osquery
```

## Optional: Kernel driver

osquery does not require a kernel driver currently.
There are medium priority plans to extend table data collection into the kernel
as well as use kernel frameworks to protect the daemon and log data.

We include an optional [kernel driver](../deployment/kernel-linux) that implements an example osquery table.

\* You may also set a different config plugin using `/etc/osquery/osquery.flags`.<br />
\** We do not recommend using the latest/unstable package as it is built
from our master branch and does not guarentee safety.
