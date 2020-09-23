# Anomaly detection with osquery

An osquery deployment can help you establish an infrastructural baseline, allowing you to detect malicious activity using scheduled queries.

This approach will help you catch known malware ([WireLurker](https://bits.blogs.nytimes.com/2014/11/05/malicious-software-campaign-targets-apple-users-in-china/), IceFog, Imuler, etc.), and more importantly, unknown malware. Let's look at macOS startup items for a given laptop using [osqueryi](../introduction/using-osqueryi.md):

```sh
$ osqueryi
osqueryi> SELECT * FROM startup_items;
+--------------+----------------------------------------------------------+
| name         | path                                                     |
+--------------+----------------------------------------------------------+
| Quicksilver  | /Applications/Quicksilver.app                            |
| iTunesHelper | /Applications/iTunes.app/Contents/MacOS/iTunesHelper.app |
| Dropbox.app  | /Applications/Dropbox.app                                |
+--------------+----------------------------------------------------------+
```

We see some pretty standard applications that run at boot, like iTunes and Dropbox.

Now imagine this same system is compromised at a later date.

We can use osquery's log aggregation capabilities to easily pinpoint when the attack occurred and what was installed.

## Looking at the logs

Using the [log aggregation guide](log-aggregation.md), you will receive log lines like the following in your datastore (ElasticSearch, Splunk, etc.):

```json
{
    "name": "startup_items",
    "action":  "added",
    "columns": {
      "name":  "Phone.app",
      "path":  "/Applications/Phone.app"
    },
    "hostname":  "ted-osx.local",
    "calendarTime":  "Fri Nov  7 09:42:42 2014",
    "unixTime":  "1415382685",
    "epoch": "314159265",
    "counter": "1"
}
```

It's clear that a suspicious application called "Phone" was added to this host's set of startup items on Nov 7th at 09:42 AM.

### Case-study: WireLurker

In November 2015, Palo Alto Networks [discovered](https://unit42.paloaltonetworks.com/wirelurker-new-era-os-x-ios-malware/) a new piece of macOS malware called Wirelurker.

If you have osquery deployed, you can search for their static IOCs (indicators of compromise):

```SQL
SELECT *
  FROM launchd
  WHERE path = '/Library/LaunchDaemons/com.apple.machook_damon.plist'
  OR path = '/Library/LaunchDaemons/com.apple.globalupdate.plist';
```

Better yet, you can generically detect WireLurker or other persistent malware using launchd and the following scheduled query, which will keep track of new, unique additions to your infrastructure:

```SQL
SELECT path, label, program_arguments, inetd_compatibility, root_directory
  FROM launchd;
```

This method has the distinct advantage of detecting malicious applications like WireLurker based on their behaviors rather than specific IOCs.
