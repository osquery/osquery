---
title: FAQ
permalink: /docs/faq/
redirect_from: /faq/index.html
---

### What operating systems does osquery support?
Apple macOS 10.11-10.13, any Linux flavor providing a glibc version 2.13 or newer, Windows 8+, and FreeBSD 10+ available through ports. Every supported OS is integrated into the osquery CI build and test processes. Additional operating systems package manager integrations are tested and supported by the osquery community.

### What information does osquery provide?
osquery produces information in the form of [tables](/schema/index.html) and events. Tables are equivalent to SQL/SQLite tables except they generate data at query time. When you run `select * from time;` the result will be the current time! Events are a bit more complicated but essentially log operating system events in real time so tables may emit the real time results when the next appropriate query runs, sort of like flushing a queued buffer.

### How do I manage osquery?
Management can be simple and flexible. The osquery daemon uses a configuration input plugin and logging output plugin. By default both use a filesystem path. Read [using `osqueryd`](https://osquery.readthedocs.org/en/latest/introduction/using-osqueryd/) for an overview of configuration.

osquery can be controllable in real time through community-supported management services. These complimentary services and open source projects are documented in our configuration guide. And writing your own configuration input and logging output plugins is supported and [encouraged](https://osquery.readthedocs.org/en/latest/development/config-plugins/).

### Does osquery expose private information?
There are no explicit privilege escalation methods built into osquery. The `osqueryi` shell runs independently of the daemon. The results logged by the daemon will be private to the host unless a log aggregation approach is implemented by your enterprise.

The osquery community respects developer and user privacy! We include a "non-goal" of exposing sensitive information like browsing history within tables. The osquery tools include 0 callback requests and 0 auto-updating, auto-diagnostic capabilities.

### Where is the osquery road map?
Feature requests and priority are managed through GitHub issues. Larger engineering/design efforts are tagged with "RFC". Please join our [Slack team]({{ site.slack_url }}) to discuss any roadmap questions and join the `#officehours` discussion for Bi-Weekly meetups.
