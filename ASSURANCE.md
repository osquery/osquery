# The Security Assurance Case for osquery

This document describes why we think the osquery agent is adequately secure software. In other words, this document is
the "assurance case" for osquery. This is a living document, and is the result of continuous threat-modeling during
osquery's continued development and maintenance.

This document also serves as detailed documentation of the basic security principles of osquery's development, and the
specific threat cases that the team of maintainers have thought about and attempted to mitigate.

## Security Design Considerations of osquery

The following is a list of high-level considerations for security, and efforts that osquery and its team of maintainers
implement in the current version of the software.

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

osquery makes use of system-provided access control permissions to restrict access to the following osquery assets:

- Reading and writing storage and cached content used by osquery, a.k.a., the RocksDB storage layer
- Reading and writing status logs and results logs, when osquery logs are written to the filesystem
- Reading and writing to the osquery extensions socket (or Pipe, on Windows)

### Integrity

#### Limited attack surface

osquery never listens on network interfaces. If it is configured to use the network at all, it is opt-in, and always a
poll model.

osquery minimizes its exposure to user-controlled data on disk by relying on access through OS-provided APIs wherever
possible. When osquery performs file parsing, it usually does so within third-party libraries that are statically
linked into osquery.

The osquery maintainers respond to known vulnerabilities in third-party libraries by being responsive to vulnerability
disclosures, upgrading osquery to use the fixed version of the associated dependency, and making the new version of
osquery available at the very next release cycle, if not sooner (urgent security issues may be addressed in an
out-of-cycle "point release").

#### Daemon runs as root

The recommended, and default, way to run the osquery daemon is as root (or Administrator, on Windows).

- Its files are owned as root (config, RocksDB) to resist tampering
- Extensions must also run as root, and communicate over an IPC restricted to root
- When osquery runs as root, it enforces additional file permission checks on the osquery core executable file and that
  of any extensions. For example, a user-controlled directory or binary should not be run as root, since osquery will
  fork and exec itself, which may lead to TOCTOU bugs. To prevent this, osquery checks for the secure set of file
  permissions during its startup, and quits with a warning if the permissions are insufficient, unless the user
  overrides this check with a flag.

#### No self-update feature

The osquery agent will never update or replace itself. The sysadmin is in control of when to update, using their method
of choice for software update management.

#### No methods to modify data on the system

Making no changes to the existing host system (its configuration or its data) is a goal that osquery seeks to achieve,
but on a best-effort basis. The maintainers enforce this as a policy for the acceptance of any new contributed
code in osquery. If we are made aware of violations of this rule, we treat them as high priority bugs and promptly fix
them. Where it is for some reason unavoidable, we will document any exceptions here.

#### No dynamic linking

The osquery executable is self-contained and statically linked, so it has no external library dependencies except the
absolute minimum required to load on each platform that it supports. This allows osquery to control the version of its
third-party dependencies (it will not be subject to outdated dynamic libraries on a host), and helps osquery avoid
certain kinds of library injection privilege-escalation attacks on the host.

#### Code-signed releases

### Availability

#### Minimal configuration by default

#### Watchdog

The osquery agent operates as a watchdog process and a worker process, with one forking the other at osquery startup.
The intent of the watchdog process is to enforce limits on resource use by the worker process, but one side-effect of
that is that it mitigates certain denial-of-service risks. For example, a poorly crafted query that would otherwise run
on forever, or intentionally planted data on the host that has been crafted specifically to cause a denial-of-service in
the osquery agent. Either of those would trigger the watchdog to restart osquery and temporarily ban the query that
exhibited the problematic behavior.

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

osquery agent must trust:

- its config server, if using a remote server to deliver the osquery config
- the person issuing queries, which is the same role as can modify the config

osquery attempts to mitigate an attacker:

- on another host with network connectivity to the osquery host, or positioned as an agent-in-the-middle on the network
- on the osquery host but with standard non-root privilege

Also in the threat model, but for which osquery does _not_ currently have mitigations for:

- an attacker that has successfully elevated to root privilege, and subverts or kills the osquery process

### Assets

- osquery executable
- osquery config (may contain threat-hunting queries)
- local database backing store (RocksDB)
- osquery's own logs
- osquery's extension socket (or named pipe, on Windows)

### Threat agents

- Remote attacker
- Network agent-in-the-middle
- Attacker on the osquery host, with User privilege
- Attacker on the osquery host, with Root privilege
- Compromised or maliciously controlled osquery config server

### Vulnerabilities in third-party library dependencies

- How we learn of newly disclosed vulnerabilities in osquery's dependencies (periodic checking; news)
- Rapid update: how we are able to respond to them quickly and update a dependency ([example](https://github.com/osquery/osquery/commit/0e9efb1497037ded21e8679dda09547d5b0fecd0) demonstrating how one may update a third-party dependency.)
- About false positives: sometimes a vulnerability in a dependency does not affect osquery
