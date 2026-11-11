# Installing osquery on Linux

A 'universal' Linux package can be created for each package distribution system. These packages contain the osquery daemon, shell, example configuration and a systemd service unit. Note that the `osqueryd.service` unit does not automatically start the daemon until a configuration file is created (see "Running osquery," below).

Each osquery tag (stable release) is published to **yum** and **apt** repositories for our supported operating systems: [https://osquery.io/downloads](https://osquery.io/downloads/).

The default packages create the following structure:

```sh
/etc/osquery/
/etc/sysconfig/osqueryd # or /etc/default/osqueryd on Debian/Ubuntu
/opt/osquery/bin/osqueryctl
/opt/osquery/bin/osqueryd
/usr/local/bin/osqueryi -> /opt/osquery/bin/osqueryd
/usr/local/bin/osqueryctl -> /opt/osquery/bin/osqueryctl
/usr/lib/systemd/system/osqueryd.service
/opt/osquery/share/osquery/certs/certs.pem
/opt/osquery/share/osquery/lenses/{*}.aug
/opt/osquery/share/osquery/packs/{*}.conf
/opt/osquery/share/osquery/osquery.example.conf
/var/log/osquery/
/var/osquery/
```

## Installing osquery

To install osquery, follow the instructions on the [Downloads](https://osquery.io/downloads/official) page according to your distro.

> NOTICE: Linux systems running `journald` will collect logging data originating from the kernel audit subsystem (something that osquery enables) from several sources, including audit records. To avoid performance problems on busy boxes (specially when osquery event tables are enabled), it is recommended to mask audit logs from entering the journal with the following command `systemctl mask --now systemd-journald-audit.socket`.

## Running osquery

To start a standalone osquery use: `osqueryi`. This does not need an osquery server or service. All the table implementations are included!

After exploring the rest of the documentation you should understand the basics of configuration and logging. These and most other concepts apply to `osqueryd`, the daemon, too. To start the daemon:

```sh
sudo cp /opt/osquery/share/osquery/osquery.example.conf /etc/osquery/osquery.conf
sudo systemctl start osqueryd
```

> NOTICE: The interactive shell and daemon do NOT communicate!

## Legacy SysV Init (`init.d`)

Official Linux packages ship only a `systemd` unit (`osqueryd.service`). If you are running osquery on a distribution that uses SysV init instead of `systemd`, you can install the following sample script to `/etc/init.d/osqueryd` (with `chmod 0755 /etc/init.d/osqueryd`):

```sh
#!/bin/sh
#
# osqueryd 	Start/Stop the osquery daemon.
#
# chkconfig: 345 90 60
# Description:
#  With osquery, you can use SQL to query low-level
#  operating system information. Under the hood, instead
#  of querying static tables, these queries dynamically execute
#  high-performance native code. The results of the
#  SQL query are transparently returned to you quickly and easily
#
### BEGIN INIT INFO
# Provides: osquery osqueryd
# Required-Start: $local_fs $syslog
# Required-Stop: $local_fs $syslog
# Default-Start:  3 4 5
# Default-Stop: 0 1 6
# Short-Description: run osqueryd daemon
# Description:
#   With osquery, you can use SQL to query low-level
#   operating system information. Under the hood, instead
#   of querying static tables, these queries dynamically execute
#   high-performance native code. The results of the
#   SQL query are transparently returned to you quickly and easily
#
### END INIT INFO

if [ -z $RETVAL ]; then RETVAL=0; fi
if [ -z $PROG ]; then PROG="osqueryd"; fi
if [ -z $EXEC ]; then EXEC=/opt/osquery/bin/osqueryd; fi
if [ -z $FLAGS_PATH ]; then FLAGS_PATH=/etc/osquery/osquery.flags; fi
if [ -z $REAL_CONFIG_PATH ]; then REAL_CONFIG_PATH=/etc/osquery/osquery.conf; fi
if [ -z $LOCKFILE ]; then LOCKFILE=/var/lock/osqueryd; fi
if [ -z $PIDFILE ]; then PIDFILE=/var/run/osqueryd.pidfile; fi
if [ -z $OLD_PIDFILE ]; then OLD_PIDFILE=/var/run/osqueryd.pid; fi
if [ -z $UID ]; then UID=$(id -u); fi

if [ $UID -eq 0 ] && [ -e /etc/default/$PROG ]; then
  . /etc/default/$PROG
elif [ $UID -eq 0 ] && [ -e /etc/sysconfig/$PROG ]; then
  . /etc/sysconfig/$PROG
fi

if [ -e /etc/init.d/functions ]; then
  . /etc/init.d/functions
fi

if [ ! -e $FLAGS_PATH ] && [ ! -e $REAL_CONFIG_PATH ]; then
  echo "No config file found at $REAL_CONFIG_PATH"
  echo "Additionally, no flags file or config override found at $FLAGS_PATH"
  echo "See '/opt/osquery/share/osquery/osquery.example.conf' for an example config."
  RETVAL=1
fi

move_pidfile() {
  if [ -f $OLD_PIDFILE ]; then
    # Support for deprecated pidfile location.
    mv $OLD_PIDFILE $PIDFILE
  fi
}

ensure_root() {
  if [ $UID -ne 0 ] ; then
    echo "User has insufficient privilege."
    RETVAL=1
  fi
}

start() {
  ensure_root
  move_pidfile

  ARGS=""
  if [ -f $PIDFILE ]; then
    PID=$(cat $PIDFILE)
    PROCNAME=$(ps -p $PID -o comm\=)
    if [ "$PROCNAME" = "$PROG" ]; then
      return 0
    else
      # osqueryd pidfile exists but it's not running
      rm $PIDFILE
    fi
  fi

  if [ -e $FLAGS_PATH ]; then ARGS="$ARGS --flagfile=$FLAGS_PATH"; fi
  if [ -e $REAL_CONFIG_PATH ]; then ARGS="$ARGS --config_path=$REAL_CONFIG_PATH"; fi

  $EXEC $ARGS \
        --pidfile=$PIDFILE \
        --daemonize=true
  RETVAL=$?
}

stop() {
  ensure_root
  move_pidfile

  if [ ! -f $PIDFILE ] ; then
    RETVAL=0
  else
    PID=$(cat $PIDFILE)
    # Terminate the daemon and watchers
    pkill -g $PID
    # Allow the event threads to tear down
    ( while kill -0 $PID >/dev/null 2>&1; do sleep 0.2; done ) & DPID=$!
    # If the event threads are still running after 5 seconds, kill them
    ( sleep 5 && pkill -9 -g $PID && kill -9 $DPID ) 2>/dev/null & WPID=$!
    if wait $DPID 2>/dev/null; then
      pkill -9 -P $WPID
      wait $WPID
    fi
    rm -f $PIDFILE
  fi
}

restart() {
  stop
  start
}

status() {
  if [ -f $PIDFILE ]; then
    PID=$(cat $PIDFILE)
    PROCNAME=$(ps -p $PID -o comm\=)
    if [ "$PROCNAME" = "$PROG" ]; then
      echo "$PROG is already running: $PID"
      RETVAL=0
    else
      # osqueryd pidfile exists but it's not running
      echo "$PROG is not running but a stale pidfile was found."
      RETVAL=7
    fi
  elif [ -f $OLD_PIDFILE ]; then
    PID=$(cat $OLD_PIDFILE)
    PROCNAME=$(ps -p $PID -o comm\=)
    if [ "$PROCNAME" = "$PROG" ]; then
      echo "$PROG is already running (old pidfile): $PID"
      RETVAL=0
    else
      # osqueryd pidfile exists but it's not running
      echo "$PROG is not running but a stale old pidfile was found."
      RETVAL=7
    fi
  else
    echo "$PROG is not running. no pidfile found."
    RETVAL=7
  fi
}

usage() {
  echo "Usage: $0 {start|stop|status|restart}"
  RETVAL=2
}

case "$1" in
    start) start ;;
    stop) stop ;;
    restart) restart ;;
    status) status ;;
    *) usage ;;
esac

exit ${RETVAL}
```
