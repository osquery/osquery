You can optionally build with BroIDS support.

## Install dependencies

Use osquery's build scripts to install CAF and Broker.

```
$ ./tools/provision.sh install osquery/osquery-local/caf
$ ./tools/provision.sh install osquery/osquery-local/broker
```

## Enable Bro

```
$ SKIP_BRO=0 make -j 4
```

