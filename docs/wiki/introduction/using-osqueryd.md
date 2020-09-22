# Using osquery

`osqueryd` is the host monitoring daemon that allows you to **schedule** queries and record OS state changes. The daemon aggregates query results over time and generates logs, which indicate state change according to each query. The daemon also uses OS eventing APIs to record monitored file and directory changes, hardware events, network events, and more.

The installation and deployment guides are mostly focused on the osquery daemon lifecycle. On Linux, the daemon starts as an SystemV initscript; on macOS as a launch daemon. The service is highly configurable and extendable.

## Configuration and query schedule

The primary daemon feature is executing a query schedule. This schedule is defined in an [osquery configuration](../deployment/configuration.md) and includes a list of semi-broad queries and their interval. The interval is an approximate time to run the query.

```json
{
  "usb_devices": {
    "query": "SELECT vendor, model FROM usb_devices;",
    "interval": 60
  }
}
```

This simple **usb_devices** query will run approximately every 60 seconds on the host running `osqueryd`.

## Logging and reporting

Each query represents a monitored view of your operating system. The first time a scheduled query runs, it logs every row in the resulting table with the "added" action. In this example, on a macOS laptop, after the first 60 seconds it would log:

```json
[
  {"model":"XHCI Root Hub SS Simulation","vendor":"Apple Inc."},
  {"model":"XHCI Root Hub USB 2.0 Simulation","vendor":"Apple Inc."},
  {"model":"BRCM20702 Hub","vendor":"Apple Inc."},
  {"model":"Internal Memory Card Reader","vendor":"Apple"},
  {"model":"Apple Internal Keyboard \/ Trackpad","vendor":"Apple Inc."},
  {"model":"Bluetooth USB Host Controller","vendor":"Apple Inc."}
]
```

If there are no USB devices added to or removed from the laptop, this query would never log a result again. The query would still run every 60 seconds, but the results would match the previous run, and thus no state change would be detected. If a USB memory stick was inserted and left in the laptop for 60 seconds, the daemon would log:

```json
[
  {"model":"U3 Cruzer Micro","vendor":"SanDisk Corporation"}
]
```

Each line in the results is decorated with a bit more information, as described in the [logging](../deployment/logging.md) guide. This includes time, hostname, added or removed action, etc.
