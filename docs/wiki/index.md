osquery is an operating system instrumentation framework for Windows, OS X (macOS), Linux, and FreeBSD. The tools make low-level operating system analytics and monitoring both performant and intuitive.

osquery exposes an operating system as a high-performance relational database. This allows you to write SQL queries to explore operating system data. With osquery, SQL tables represent abstract concepts such as running processes, loaded kernel modules, open network connections, browser plugins, hardware events or file hashes.

## Getting Started

If you're interested in **installing osquery** check out the install guide for [Windows](installation/install-windows.md), [macOS](installation/install-osx.md), [Linux](installation/install-linux.md), and [FreeBSD](installation/install-freebsd.md).

If you're interested in **developing queries** and **exploring** tables, check out [using osqueryi](introduction/using-osqueryi.md).

If you're interested in **deploying osquery** to provide your organization with deeper insight into your Linux, FreeBSD, macOS, and Windows hosts check out the [using osqueryd guide](introduction/using-osqueryd.md).

If you're interested in **extending one of the existing osquery tools** or improving core libraries, read the developer documentation pages. You should start with "[building the code](development/building.md)" and "[contributing code](development/contributing-code.md)".

If you're interested in **integrating osquery** into your own tool, check out the [osquery SDK](development/osquery-sdk.md).

## High Level Features

The high-performance and low-footprint distributed host monitoring daemon, **osqueryd**, allows you to schedule queries to be executed across your entire infrastructure. The daemon takes care of aggregating the query results over time and generates logs which indicate state changes in your infrastructure. You can use this to maintain insight into the security, performance, configuration, and state of your entire infrastructure. **osqueryd**'s logging can integrate into your internal log aggregation pipeline, regardless of your technology stack, via a robust plugin architecture.

The interactive query console, **osqueryi**, gives you a SQL interface to try out new queries and explore your operating system. With the power of a complete SQL language and dozens of useful tables built-in, **osqueryi** is an invaluable tool when performing incident response, diagnosing a systems operations problem, troubleshooting a performance issue, etc.

osquery is cross platform. Even though osquery takes advantage of very low-level operating system APIs, you can build and use osquery on Windows, MacOS, Ubuntu, CentOS and other popular enterprise Linux distributions. This has the distinct advantage of allowing you to be able to use one platform for monitoring complex operating system state across your entire infrastructure. Monitor your corporate Windows or MacOS clients the same way you monitor your production Linux servers.

To make deploying osquery in your infrastructure as easy as possible, osquery comes with native packages for all supported operating systems. There is extensive tooling and documentation around creating packages so packaging and deploying your custom osquery tools can be just as easy too.

To assist with the rollout process, the osquery user guide has detailed documentation on internal deployment. osquery was built so that every environment specific aspect of the toolchain can be hot-swapped at run-time with custom plugins. Use these interfaces to deeply integrate osquery into your infrastructure if one of the several existing plugins do not suit your needs.

Additionally, osquery's codebase is made up of high-performance, modular components with clearly documented public APIs. These components can be easily strung together to create new, interesting applications and tools. Language bindings exist for many languages using a Thrift interface, so you can continue using comfortable and familiar technologies.

## Getting Help

If any part of osquery is not working as expected, please create a [GitHub Issue](https://github.com/facebook/osquery/issues). Keep in touch with osquery developers and users in our Slack [https://osquery-slack.herokuapp.com/](https://osquery-slack.herokuapp.com/).

If you have long-form questions, please email [osquery@fb.com](mailto:osquery@fb.com).

## Documentation

This wiki, hosted on ReadTheDocs.org, is written in Markdown and kept within the osquery Github repository in the [docs/wiki](https://github.com/facebook/osquery/tree/master/docs/wiki) directory. Please submit changes using Github pull requests. The wiki is built automatically with every commit and available as "[latest](http://osquery.readthedocs.io/en/latest/)". A "stable" release is built alongside osquery versions using Github's tagged-releases.