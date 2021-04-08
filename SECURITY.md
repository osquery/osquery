# The Security Assurance Case for osquery

This document describes why we think the osquery agent is adequately secure software. In other words, this document is the "[assurance case](https://www.ida.org/-/media/feature/publications/a/as/a-sample-security-assurance-case-pattern/p-9278.ashx)" for osquery. This is a living document, and is the result of continuous threat-modeling during osquery's continued development and maintenance.

This document also serves as detailed documentation of osquery's security requirements, and contains a reference history of its remediated security vulnerabilities. If you find a vulnerability, please see CONTRIBUTING.md#how_to_report_vulnerabilities for how to submit a vulnerability report.

## Security Issues

This document aggregates security issues (weaknesses and vulnerabilities) affecting osquery. It tracks issues in the format:

```text
#PRNumber Title - (Optional CVE) - Fixed in Version - Optional Reporter
```

There are several types of issues that do not include a CVE or reporter.
If you find a security issue and believe a CVE should be assigned, please contact a [member of the TSC](https://github.com/osquery/osquery/blob/master/CONTRIBUTING.md#technical-steering-committee) in the osquery [Slack](https://osquery.slack.com), we are happy to submit the request and provide attribution to you.
Specifically, we will use the GitHub Security Advisory features for CVE requests.
The project maintainers will tag related issues and pull requests with the [`hardening`](https://github.com/osquery/osquery/issues?q=is%3Aissue+is%3Aopen+label%3Ahardening) label. There may be changes with this label that are not directly security issues.

If you are editing this document please feel encouraged to change this format to provide more details. This is intended to be a helpful resource so please keep content valuable and concise.

- #6197 osquery does not validate TLS SNI hostname - CVE-2020-1887 - 4.2.0 - Timothy Britton of Apple
- #3786 Migrate from `boost::regex` to `re2` - unresolved - Ruslan Habalov and Felix Wilhelm of the Google Security Team
- #3785 `ie_extensions` susceptible to SQL injection - CVE-2017-15026 - 2.9.0 - Ruslan Habalov and Felix Wilhelm of the Google Security Team
- #3783/#3782 `safari_extensions` should not use parent paths for privilege dropping - CVE-2017-15027 - 2.9.0 - Ruslan Habalov and Felix Wilhelm of the Google Security Team
- #3781 `known_hosts` should drop privileges - CVE-2017-15028 - 2.9.0 - Ruslan Habalov and Felix Wilhelm of the Google Security Team
- #3770/#3775 `libxml2` (v2.9.5) and `libarchive` (v3.3.2) updated - 2.9.0
- #3767 `augeas` (v1.8.1) mitigates CVE-2017-7555 - 2.9.0 - Ruslan Habalov and Felix Wilhelm of the Google Security Team
- #3133 Bad output size for TLS compression - 2.4.0 - Facebook Whitehat
- #2447 Multiple fixes to macOS `crashes` - 2.0.0 - Facebook Whitehat and zzuf
- #2330 Add size checks to `package_bom` - 2.0.0 - Facebook Whitehat
- #1598 `readFile` TOCTOU error - 1.6.0 - NCC Group
- #1596 Uncaught exception in config JSON parsing - 1.6.0 - NCC Group
- #1585 Various comparisons of integers of different signs - 1.6.0 - NCC Group
- #993 Add restricted permissions to RocksDB - 1.4.5 - Anonymous security review
- #740 Add hardening compile flags and `-fPIE` - 1.4.1 - Anonymous security review
- #300 Add restricted permissions to osqueryd logging - 1.0.4

## Security Requirements Met by Functionality

### Confidentiality

#### No Retrieval of Sensitive User-owned Data

- Certain tables disabled by default, additional tables can be disabled

#### Use of HTTPS (TLS)

- HTTPS (specifically the TLS v1.2 protocol) is used to encrypt all communications

#### No custom cryptography (only well-known libraries)

#### No network connectivity to third parties

#### Does not accept incoming network connections

#### Does not 'shell out' to other binaries for data collection

#### Access control functions

### Integrity

#### Limited attack surface

#### Daemon runs as root

- Its files are owned as root (config, RocksDB) to resist tampering
- Extensions must also run as root, communicate over IPC restricted to root

#### No self-update feature

#### No methods to modify data on the system

#### No dynamic linking

#### Code-signed releases

### Availability

#### Minimal configuration by default

#### Watchdog

## Security Implemented in Development Lifecycle Processes

- configuration management via GitHub, can track the changes, who made them, and when they were made
- we use GitHub for managing the source code and issue tracker; it has an authentication and authorization system
- limited number of individuals with commit access: [Technical Steering Committee](https://github.com/orgs/osquery/teams/technical-steering-committee), whom have control over the GitHub organization, and whom regularly perform code review and merge actions
- all changes are made in branches, and then merged only after review
- second-party review required to merge contribution
- cppcheck
- clang-tidy
- clang sanitizers
- fuzzed by oss-fuzz ([project page](https://github.com/google/oss-fuzz/tree/master/projects/osquery))
- modern C++ limiting memory-unsafe language use, not C (except where in third-party library dependencies)
- warnings as errors: see [the cmake configuration for the project](https://github.com/osquery/osquery/blob/master/cmake/flags.cmake), Wall and pedantic among others are set
- reproducible builds
- third-party dependencies retrieved using commit hash
- opting into compile-time security mitigations (stack protectors, full relro, and other compiler-available hardening options): see [the cmake configuration for the project](https://github.com/osquery/osquery/blob/master/cmake/flags.cmake)
- how we protect code-signing secrets / key material

## Threat Model

- osquery agent must trust its config server

### Assets

- osquery executable
- osquery config (may contain threat-hunting queries)
- local database backing store (RocksDB)

### Threat agents

- Remote attacker
- Network man-in-the-middle
- Malware on host, with User privilege
- Malware on host, with Root privilege

### Vulnerabilities in third-party library dependencies

- How we learn of newly disclosed vulnerabilities in osquery's dependencies (periodic checking; news)
- Rapid update: how we are able to respond to them quickly and update a dependency ([example](https://github.com/osquery/osquery/commit/0e9efb1497037ded21e8679dda09547d5b0fecd0) demonstrating how one may update a third-party dependency.)
- About false positives: sometimes a vulnerability in a dependency does not affect osquery
