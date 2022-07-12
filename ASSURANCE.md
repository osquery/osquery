# The Security Assurance Case for osquery

This document details the basic security principles of osquery's development, the specific threat cases that the team
of maintainers have thought about, and how we have attempted to mitigate them.

In other words, this describes why we think the osquery agent is adequately secure software: the "assurance case" for
osquery. This is a living document, and is the result of continuous threat-modeling during osquery's continued
development and maintenance.

## The osquery Threat Model

The core osquery agent is a single-executable daemon, running on each host that is to be queried.

The osquery agent does not trust:

- users on the osquery host with standard non-root privilege (no interaction with the users on the host)
- network third-parties, including external network services (see "No Network Connectivity to Third Parties") or
agents-in-the-middle on the network (see "use of HTTPS")

However, the osquery agent _must_ trust:

- its config server, if using a remote server to deliver the osquery config
- the person issuing queries, which is the same role as can modify the config

Note that in this threat model, osquery does _not_ currently have mitigations for:

- an attacker that has successfully elevated to root privilege, and subverts or kills the osquery process

### osquery's Assets

- osquery executable
- osquery config (may contain threat-hunting queries)
- local database backing store (RocksDB)
- osquery's own logs
- osquery's extension socket (or named pipe, on Windows)

### osquery's Threat Agents

- Remote attacker
- Network agent-in-the-middle
- Attacker on the osquery host, with User privilege
- Attacker on the osquery host, with Root privilege
- Compromised or maliciously controlled osquery config server
- Supply-chain threats (vulnerabilities in third-party dependencies)

### Vulnerabilities in Third-party Library Dependencies

Updating native C/C++ library dependencies is a relatively manual process compared to package-managed programming
languages. We learn of newly disclosed vulnerabilities in osquery's dependencies by following community news and
maintaining a general awareness of new announcements. It's a shared responsibility. There is an effort, currently in
progress, to add a scheduled automated dependency checking script to our CI workflows. When complete, it should provide
more timely alerts.

The osquery maintainers make a best effort to rapidly update vulnerable libraries with a new version of osquery, when
needed. See an [example](https://github.com/osquery/osquery/commit/0e9efb1497037ded21e8679dda09547d5b0fecd0)
demonstrating how we update a third-party dependency.)

Finally, a note: sometimes security-dependency-checking tools generate false positives. There may be a vulnerability
in one of osquery's dependencies, but for one reason or another it may not actually affect osquery. We still make an effort
to update to fixed versions of libraries, but more or less urgently depending on osquery's actual exposure to the risk.
Refer to the osquery wiki where we maintain an [updated impact assessment of known issues](https://osquery.readthedocs.io/en/latest/deployment/dependency-security/)
that have been reported as being vulnerabilities in osquery's third-party dependencies.

## Security Design Considerations of osquery

The following is a list of high-level considerations for security, and efforts that osquery and its team of maintainers
implement in the current version of the software.

### Confidentiality Considerations

#### Use of HTTPS (TLS)

The current version of osquery uses HTTPS (specifically, the TLS v1.2 protocol), to encrypt all of its communications.

#### No Custom Cryptography

Only well-known, industry standard encryption libraries are used in osquery. Specifically, OpenSSL.

#### No Network Connectivity to Third Parties

Here, we define a "third-party" as any remote server _other than the ones that deliver the agent's config or receive
its logs_, which for many osquery deployments may be hosted by a SaaS provider (not on-premises).

With one or two opt-in exceptions (_e.g._, use of the cURL table, or certain configurations of the yara table), the
osquery core agent will never make an outbound network connection to a third-party server.

In no case will the osquery core agent ever listen for or accept inbound network connections.

#### Does Not 'shell out' to Other Binaries for Data Collection

The osquery executable will be the only process; it spawns two instances (a worker process and a watchdog). It does
not fork/subprocess/shell out to any other executables. An optional extension interface allows osquery to communicate
with osquery extensions (separate executables), which are allowed to invoke their own additional processes.

#### Access Control Functions

osquery makes use of system-provided access control permissions to restrict access to the following osquery assets:

- Reading and writing storage and cached content used by osquery, a.k.a., the RocksDB storage layer
- Reading and writing status logs and results logs, when osquery logs are written to the filesystem
- Reading and writing to the osquery extensions socket (or Pipe, on Windows)

### Integrity Considerations

#### Limited Attack Surface

As mentioned, osquery never listens on network interfaces. If it is configured to use the network at all, it is
opt-in, and always using a poll model.

osquery minimizes its exposure to user-controlled data on disk by relying on access through OS-provided APIs wherever
possible. When osquery performs file parsing, it usually does so within third-party libraries that are statically
linked into osquery.

The osquery maintainers react to known vulnerabilities in third-party libraries by being responsive to vulnerability
disclosures, upgrading osquery to use the patched version of the associated dependency, and making the new version of
osquery available at the very next release cycle, if not sooner (urgent security issues may be addressed in an
out-of-cycle "point release").

#### Daemon Runs as root (or Administrator)

The recommended, and default, way to run the osquery daemon is as root (or Administrator, on Windows).

- Its files are owned as root (config, RocksDB) to resist tampering
- Extensions must also run as root, and communicate over an IPC restricted to root
- When osquery runs as root, it enforces additional file permission checks on the osquery core executable file and that
  of any extensions. For example, a user-controlled directory or binary should not be run as root, since osquery will
  fork and exec itself, which may lead to TOCTOU bugs. To prevent this, osquery checks for the secure set of file
  permissions during its startup, and quits with a warning if the permissions are insufficient, unless the user
  overrides this check with a flag.

#### No Self-update Feature

The osquery agent will never update or replace itself. The sysadmin is in control of when to update, using their method
of choice for software update management. Products that ship with or include the osquery agent may have self-update
features, but the core agent itself does not.

#### No Methods to Modify System State

Making no changes to the existing host system (its configuration or its data) is a goal that osquery seeks to achieve,
but on a best-effort basis. The maintainers enforce this as a policy for the acceptance of any new contributed
code in osquery. If we are made aware of violations of this rule, we treat them as high priority bugs and promptly fix
them. Where it is for some reason unavoidable, we will document any exceptions here.

Exceptions:

- To monitor the Linux Audit subsystem for events (`--audit_allow_config`), osquery changes kernel Audit settings.
- The osquery installer, or its included convenience scripts, may install the osquery daemon to launch as a service.

#### Static Linking of Libraries

The osquery executable is self-contained and statically linked, so it has no external library dependencies except the
absolute minimum required to load on each platform that it supports. This allows osquery to control the version of its
third-party dependencies (it will not be subject to outdated dynamic libraries on a host), and helps osquery avoid
certain kinds of library injection privilege-escalation attacks on the host.

#### Code-signed Releases

Every release of osquery is code-signed, on every supported platform.

### Availability Considerations

Availability refers to the agent's goal of being resilient to communications failure, shutdown, or other kinds
of denial-of-service condition. This is one of the three traditional pillars of security design, after confidentiality
and integrity.

#### Minimal Configuration by Default

The less functionality is enabled, the fewer things can hypothetically go wrong: that is the reasoning behind the
design principle of osquery requiring an explicit opt-in to enable some of its functionality.

#### Watchdog

The osquery agent operates as a watchdog process and a worker process, with one forking the other at osquery startup.
The intent of the watchdog process is to enforce limits on resource use by the worker process, but one side-benefit
is that it mitigates certain denial-of-service risks. For example, a poorly crafted query that would otherwise run
on forever, or intentionally planted data on the host that has been crafted specifically to cause a denial-of-service in
the osquery agent. Either of those would trigger the watchdog to restart osquery and temporarily ban the query that
exhibited the problematic behavior, reducing the impact on operations.

## Security Implemented in Development Lifecycle Processes

The osquery development lifecycle includes many practices to mitigate security issues from entering the codebase:

- configuration management via git, where we can track the changes, who made them, and when they were made
- issue tracking, code review discussions and contribution management via GitHub
- use of GitHub's authentication and authorization system to granularly control access permissions
- limited number of individuals with commit access: the [Technical Steering
  Committee](https://github.com/orgs/osquery/teams/technical-steering-committee) has control over the GitHub
  organization, and its members regularly perform code review and merge actions
- all changes are made in branches, and then merged only after review
- second-party review required to merge a contribution
- use of cppcheck
- use of clang-tidy to enforce readable code formatting, making bugs easier to spot
- use of clang sanitizers, to automatically detect memory-corruption errors
- fuzzed by oss-fuzz ([project page](https://github.com/google/oss-fuzz/tree/master/projects/osquery))
- use of modern C++, limiting memory-unsafe language use: not C (except where in third-party library dependencies)
- using warnings as errors: see [the cmake configuration for the project](https://github.com/osquery/osquery/blob/master/cmake/flags.cmake), Wall and pedantic among others are set
- reproducible builds
- third-party dependencies are retrieved using a known commit hash from their respective repositories
- opting into compile-time security mitigations (stack protectors, full relro, and other compiler-available hardening options): see [the cmake configuration for the project](https://github.com/osquery/osquery/blob/master/cmake/flags.cmake)
- only the required subset of the TSC has access to code-signing secrets / key material, and they are protected within a
  separate GitHub repo that performs osquery release signing

See our [CONTRIBUTING doc](https://github.com/osquery/osquery/blob/master/CONTRIBUTING.md#guidelines-for-contributing-features-to-osquery-core)
for more information on our guiding principles for osquery development.
