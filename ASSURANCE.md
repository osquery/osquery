# The Security Assurance Case for osquery

This document describes why we think the osquery agent is adequately secure software. In other words, this document is
the "assurance case" for osquery. This is a living document, and is the result of continuous threat-modeling during
osquery's continued development and maintenance.

This document also serves as detailed documentation of osquery's security requirements.

## Security Requirements Met by Functionality

Existing functionality in osquery attempts to address the following categories of security requirement.

### Confidentiality

#### No Retrieval of Sensitive User-owned Data

The design intent of osquery is to collect and monitor system-level information, not the potentially private data from the
user's home directory, or their internet activity. While there is no clear line that separates the two (and the definition
of "user data" can be subjective), osquery disables certain tables by default in order to minimize its ability to
collect user data without explicit configuration. It also provides the ability to disable additional tables.

Some caveats apply:

- Disabling tables is done via the osquery config, but, osquery doesn't currently have a concept of separate access
  roles for the "can alter the osquery config" permission and the "can make a query" permission. They are the same
  level of privilege. Disabling a table, then, is establishing an intent not to collect, rather than creating an
  enforceable security boundary.
- An osquery table is enabled or disabled in its entirety, and cannot currently be enabled only, e.g., for subsets of
  the filesystem.
- Some tables are flexible and powerful enough to be used to _indirectly_ query user data.

There are no other mechanisms within osquery to guarantee the collection of user data can't happen. Anything that
can be seen by the osquery process (normally running as root), has at least the potential to be collected in a query,
even if only inadvertently.

#### Use of HTTPS (TLS)

The current version of osquery uses HTTPS (specifically, the TLS v1.2 protocol), to encrypt all of its communications.

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
