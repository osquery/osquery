osquery is an operating system instrumentation framework for Windows, OS X (macOS), and Linux. The tools make low-level operating system analytics and monitoring both performant and intuitive.

osquery exposes an operating system as a high-performance relational database. This allows you to write SQL queries to explore operating system data. With osquery, SQL tables represent abstract concepts such as running processes, loaded kernel modules, open network connections, browser plugins, hardware events or file hashes.

## Getting Started

If you're interested in **installing osquery** check out the install guide for [Windows](installation/install-windows.md), [macOS](installation/install-macos.md), and [Linux](installation/install-linux.md).

If you're interested in **developing queries** and **exploring** tables, check out [using osqueryi](introduction/using-osqueryi.md).

If you're interested in **deploying osquery** to provide your organization with deeper insight into your Linux, macOS,
and Windows hosts check out the [using osqueryd guide](introduction/using-osqueryd.md). If, as part of deploying
osquery, you've run a vulnerability analyzer on either the osquery executable or the open-source repository and it has
flagged a vulnerability in one of osquery's dependencies, please check our most up-to-date [bulletins about known issues in third-party dependencies](deployment/dependency-security.md).

If you're interested in **extending one of the existing osquery tools** or improving core libraries, read the developer documentation pages. You should start with "[building the code](development/building.md)" and read the project's "[CONTRIBUTING.md](https://github.com/osquery/osquery/blob/master/CONTRIBUTING.md)".

If you're interested in **integrating osquery** into your own tool, check out the [osquery SDK](development/osquery-sdk.md).

## High Level Features

The high-performance and low-footprint distributed host monitoring daemon, `osqueryd`, allows you to schedule queries to be executed across your entire infrastructure. The daemon takes care of aggregating the query results over time and generates logs which indicate state changes in your infrastructure. You can use this to maintain insight into the security, performance, configuration, and state of your entire infrastructure. `osqueryd`'s logging can integrate into your internal log aggregation pipeline, regardless of your technology stack, via a robust plugin architecture.

The interactive query console, `osqueryi`, gives you a SQL interface to try out new queries and explore your operating system. With the power of a complete SQL language and dozens of useful tables built-in, `osqueryi` is an invaluable tool when performing incident response, diagnosing a systems operations problem, troubleshooting a performance issue, etc.

osquery is cross-platform. Even though osquery takes advantage of very low-level operating system APIs, you can build and use osquery on Windows, macOS, Ubuntu, CentOS and other popular enterprise Linux distributions. This has the distinct advantage of allowing you to be able to use one platform for monitoring complex operating system state across your entire infrastructure. Monitor your corporate Windows or macOS clients the same way you monitor your production Linux servers.

To make deploying osquery in your infrastructure as easy as possible, osquery comes with native packages for all supported operating systems. There is extensive tooling and documentation around creating packages so packaging and deploying your custom osquery tools can be just as easy too.

To assist with the rollout process, the osquery user guide has detailed documentation on internal deployment. osquery was built so that every environment-specific aspect of the toolchain can be hot-swapped at runtime with custom plugins. Use these interfaces to deeply integrate osquery into your infrastructure, if none of the several existing plugins suit your needs.

Additionally, osquery's codebase is made up of high-performance, modular components with clearly documented public APIs. These components can be easily strung together to create new, interesting applications and tools. Language bindings exist for many languages using a Thrift interface, so you can continue using comfortable and familiar technologies.

## Getting Help

If any part of osquery is not working as expected, please create a [GitHub Issue](https://github.com/osquery/osquery/issues). Keep in touch with osquery developers and users in our Slack: [Join osquery](https://join.slack.com/t/osquery/shared_invite/zt-h29zm0gk-s2DBtGUTW4CFel0f0IjTEw).

## Documentation

This wiki, hosted on ReadTheDocs.io, is written in Markdown and kept within the osquery GitHub repository in the [docs/wiki](https://github.com/osquery/osquery/tree/master/docs/wiki) directory. Please submit changes using GitHub pull requests. The wiki is built automatically with every commit and available as "[latest](https://osquery.readthedocs.io/en/latest/)". A "stable" release of the documentation is built alongside every GitHub-tagged release of osquery.
