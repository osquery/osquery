The easiest way to install osquery on FreeBSD is via the ports tree.  Check [FreshPorts](https://www.freshports.org/sysutils/osquery) for the latest version information.

```bash
# from ports
cd /usr/ports/sysutils/osquery && make install clean

# from binary package
pkg install osquery

# using portmaster
portmaster sysutils/osquery
```
