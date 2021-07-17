# Security Vulnerability Disclosure

This document contains a reference history of osquery's remediated security vulnerabilities. If you find a
vulnerability, please see CONTRIBUTING.md#how_to_report_vulnerabilities for how to submit a vulnerability report.

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
