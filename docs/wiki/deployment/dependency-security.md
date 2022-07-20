# Security Alerts for Third-party Dependencies Used by osquery

When the osquery maintainers are made aware of a newly disclosed vulnerability in one of the third-party dependencies
built into osquery, we investigate the potential for security impact to osquery. Not all issues affect osquery, for
reasons such as:

- osquery does not exercise all code paths through every one of its dependencies
- sometimes, the issue is in the parent repository of osquery's dependency, but not the actual dependency as used
- not all code from osquery's dependencies is even present in the actual osquery executable as compiled
- the [osquery security design mitigates](https://github.com/osquery/osquery/blob/master/ASSURANCE.md) attacks and
  reduces attack surface (_i.e._, some would-be bugs in third-party dependencies are not exposed)

Below are some recent reports, and the impact assessments performed by the osquery team, if they may be useful for
you in deciding how to deploy or when to update osquery.

When osquery's maintainers decide that a dependency must be updated to address a potential security impact to osquery,
the update will typically be merged into the main branch in hours or days, but depending on the timing and perceived
risk, may not be available in a tested release of osquery until the next scheduled release version. Other times, a more
urgent response is needed and there will be an unscheduled patch release (for example 5.2.3, as opposed to planned
releases like 5.1, 5.3, 5.4 etc.).

Security issues with verified security impact to osquery will be labeled in the
[CHANGELOG](https://github.com/osquery/osquery/blob/master/CHANGELOG.md) for osquery but will not receive [security
advisories](https://github.com/osquery/osquery/security/advisories) on the osquery project page (those are reserved
specifically for issues in osquery's own codebase) or any new CVEs beyond the ones already filed against their own
upstream projects.

Lastly, realize that it is not possible to create an _exhaustive_ list, but this page may be updated as often as is
practically possible, as a convenience or reference for osquery deployment decision makers and admins. If you have a
question about the determined impact of any particular threat to a dependency, please ask in the osquery Slack or in our
GitHub issues.

## librpm prior to 4.17.0, CVE-2021-20266

Conclusion: This has the potential to be used to DoS a query of the affected tables (`rpm` tables).

Updated in: osquery version 5.2.3.

## OpenSSL 1.1.1l, CVE-2022-0778

Conclusion: This impacted osquery where it does certificate parsing.

Updated in: osquery version 5.2.3.

## OpenSSL 1.1.1n, CVE-2022-1292

Report excerpt:

> The c_rehash script does not properly sanitise shell metacharacters to prevent command injection. This script is
> distributed by some operating systems in a manner where it is automatically executed. On such operating systems, an
> attacker could execute arbitrary commands with the privileges of the script. Use of the c_rehash script is considered
> obsolete and should be replaced by the OpenSSL rehash command line tool.

Conclusion:

The vulnerable `c_rehash` Perl script is not used in the osquery build process, nor is it included in the build
artifacts or release packages. Therefore, osquery is not affected.

## sqlite 3.35.5, CVE-2022-21227

Report excerpt:

> The package sqlite3 before 5.0.3 are vulnerable to Denial of Service (DoS) which will invoke the `toString` function
> of the passed parameter. If passed an invalid Function object it will throw and crash the V8 engine.

Conclusion:

A key detail of this report is incorrect: it erroneously attributes a V8-specific bug in the library bindings to the
actual C library underneath. These are different projects, maintained and published by different entities. Therefore
osquery is not affected.

## sqlite 3.35.5, CVE-2021-45346

Report excerpt:

> A Memory Leak vulnerability exists in SQLite Project SQLite3 3.35.1 and 3.37.0 via maliciously crafted SQL Queries
> (made via editing the Database File), it is possible to query a record, and leak subsequent bytes of memory that
> extend beyond the record, which could let a malicious user obtain sensitive information.

Conclusion:

This is a low impact issue for osquery, because while it entails a potential information leak of the osquery process
memory, the leak is limited to disclosing _the next records in the database_. The difficulty for the attacker is also
high: they need both to supply a query to osquery and to both read and write its SQLite database file. With the
privileges required for this, there is no benefit to the attacker; they could just acquire the same information more
directly.

Additional Technical Details:

In the attack scenario, the database file would need to be edited to extend the boundaries of certain columns, causing
sqlite to read more bytes than necessary when retrieving the column data from disk.

This is not considered a “read primitive,” since it does not allow read operations at an arbitrary offset. Due to this
limitation, the attack can only read in one direction (_i.e.,_ toward growing addresses) starting from the corrupted
column and only for the fixed amount of bytes that have been preselected when the file has been tampered on disk.
Additional checks within sqlite make sure that the read does not exceed the table storage, effectively limiting the
information leak to just neighbor records.

In order to exploit this bug, the attacker needs to either:

1) Corrupt a sqlite database on disk, enable the ATC feature of osquery and force osquery to open the tampered database
   file, then run the attacker’s choice of SQL query (either by editing query packs, or operating on the Fleet manager);
   or,
2) Corrupt an existing sqlite database on disk that is already configured under ATC and that has active queries running
   on that specific table.

Corruption requires both read and write access to the database file, in order to:

- Locate where the table starts
- Locate a suitable record to target, i.e. a record that precedes the rows that will have to be leaked
- Decode, update and rewrite the record

It should be kept in mind that the configuration files, query packs and the osquery fleet manager are managed and
operated by what the osquery security model considers administrators. These users are already able to read a large
variety of data without needing to use any exploit by issuing SQL queries or configuration updates (like a more broad
ATC configuration that extends access to the whole sqlite database file).

Running the query is however not enough on its own, since the attacker also needs to be able to read the information
leak _output_ in the results log. This is stored either in a Fleet manager, or the end storage of a logger plugin. Some
examples include S3 buckets, Kinesis, Firehose, Kafka, or (more rare) a local folder if the filesystem logger plugin was
used. For most deployments, then, the attacker needs additional credentials on multiple systems.

## zlib v1.2.11, CVE-2018-25032

Conclusion: only affects zlib compression if an attacker can fully control the parameters of a compression operation,
which is not believed to be possible in osquery. Therefore osquery was not affected.

Updated in: osquery 5.2.3.
