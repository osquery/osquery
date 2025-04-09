# osquery Changelog

<a name="5.16.0"></a>
## [5.16.0](https://github.com/osquery/osquery/releases/tag/5.16.0)

[Git Commits](https://github.com/osquery/osquery/compare/5.15.0...5.16.0)

Representing commits from 7 contributors! Thank you all.

### Table Changes

- Fix the `python_paths` table to skip unnecessary code paths when filtering by `directory` ([#8544](https://github.com/osquery/osquery/pull/8544))
- Added python packages in user directories on `python_packages` ([#8504](https://github.com/osquery/osquery/pull/8504))
- Added RHEL paths for `python_packages` table ([#8529](https://github.com/osquery/osquery/pull/8529))
- Buffer error logs in `deb_packages` table ([#8540](https://github.com/osquery/osquery/pull/8540))
- Fix `wifi_status` to correctly gather `network_name` on MacOS 14+ ([#8530](https://github.com/osquery/osquery/pull/8530))
- Fix hardware model and version on Lenovo on `system_info` ([#8534](https://github.com/osquery/osquery/pull/8534))
- Optimize `rpm_packages` and `rpm_package_files` use of query context ([#8537](https://github.com/osquery/osquery/pull/8537))

### Bug Fixes

- Fix to only deny-list scheduled queries when watchdog is enabled ([#8541](https://github.com/osquery/osquery/pull/8541))
- Switched to `wmain` to accept non-ascii characters from command line ([#8519](https://github.com/osquery/osquery/pull/8519))

<a name="5.15.0"></a>
## [5.15.0](https://github.com/osquery/osquery/releases/tag/5.15.0)

[Git Commits](https://github.com/osquery/osquery/compare/5.14.1...5.15.0)

Representing commits from 17 contributors! Thank you all.

### Table Changes

- Add arc path to `chrome_extensions` on macOS ([#8473](https://github.com/osquery/osquery/pull/8473))
- Use empty columns instead of zeroes when undefined in `socket_events` ([#8510](https://github.com/osquery/osquery/pull/8510))
- Add support for accept to macOS table `socket_events` ([#8508](https://github.com/osquery/osquery/pull/8508))
- Add all-platform user-based optimized columns ([#8496](https://github.com/osquery/osquery/pull/8496))
- Add columns to `es_process_events` ([#8506](https://github.com/osquery/osquery/pull/8506))
- Add Darwin platform optimized miscellaneous columns ([#8484](https://github.com/osquery/osquery/pull/8484))
- Add all-platform path-based optimized columns ([#8497](https://github.com/osquery/osquery/pull/8497))
- Add Windows platform optimized columns ([#8495](https://github.com/osquery/osquery/pull/8495))
- Add `hash_executable` column to `signature` table ([#8471](https://github.com/osquery/osquery/pull/8471))
- Include VSCode Insiders extensions in `vscode_extensions` table ([#8396](https://github.com/osquery/osquery/pull/8396))
- Add POSIX platforms optimized columns ([#8494](https://github.com/osquery/osquery/pull/8494))
- Add Linux platform optimized columns ([#8493](https://github.com/osquery/osquery/pull/8493))
- Add all platform process based and curl optimized columns ([#8498](https://github.com/osquery/osquery/pull/8498))
- Add Darwin platform optimized system-related columns ([#8483](https://github.com/osquery/osquery/pull/8483))
- Add Darwin platform optimized path columns ([#8482](https://github.com/osquery/osquery/pull/8482))
- Fix incorrect SID in `logged_in_users` table on windows when username and domain/device name are the same ([#8486](https://github.com/osquery/osquery/pull/8486))
- Update the `browser_firefox` table to exclude "Crash Reports" and "Pending Pings" folders ([#8478](https://github.com/osquery/osquery/pull/8478))
- Move status column to `extended_schema` for linux `socket_events` ([#8503](https://github.com/osquery/osquery/pull/8503))

### Under the Hood improvements

- Utils: Optimize default status message constructor ([#8489](https://github.com/osquery/osquery/pull/8489))

### Bug Fixes

- Fix a leak in `genAarch64PlatformInfo` ([#8462](https://github.com/osquery/osquery/pull/8462))
- Fix a leak in `DiskArbitrationEventPublisher::getProperty` ([#8463](https://github.com/osquery/osquery/pull/8463))
- Catching generic exception in order to avoid crashing when parsing windows events logs ([#8513](https://github.com/osquery/osquery/pull/8513))
- Fix leak in `windows_events` by using `scope_guard` ([#8511](https://github.com/osquery/osquery/pull/8511))
- Fixed eBPF's parsing of parent pid ([#8501](https://github.com/osquery/osquery/pull/8501))
- Fix IO objects refcounting ([#8481](https://github.com/osquery/osquery/pull/8481))

### Documentation

- Add documentation for testing macOS EndpointSecurity ([#8509](https://github.com/osquery/osquery/pull/8509))
- Add double quotes in Windows installation documentation ([#8492](https://github.com/osquery/osquery/pull/8492))
- Update expired Slack invite ([#8488](https://github.com/osquery/osquery/pull/8488))
- Update docs to correctly define `conditional_to_base64` ([#8460](https://github.com/osquery/osquery/pull/8460))

### Build

- build(deps): bump jinja2 from 3.1.4 to 3.1.5 ([#8507](https://github.com/osquery/osquery/pull/8507))
- Remove yara schema subdirectory ([#8461](https://github.com/osquery/osquery/pull/8461))
- Added chrono header file ([#8512](https://github.com/osquery/osquery/pull/8512))
- Replace usage of libaudit function removed in v3.0.7 ([#8401](https://github.com/osquery/osquery/pull/8401))
- Update xcode version for macos-14 from 14.3.1 to 15.4 ([#8467](https://github.com/osquery/osquery/pull/8467))
- Restrict python versions differently ([#8453](https://github.com/osquery/osquery/pull/8453))
- Update macOS test runner from 12 to 13 ([#8459](https://github.com/osquery/osquery/pull/8459))
- Add CVEs to the ignored lists ([#8458](https://github.com/osquery/osquery/pull/8458))
- Add a specific package build folder on Windows jobs ([#8446](https://github.com/osquery/osquery/pull/8446))
- Update all Github actions to a version using NodeJs 20 ([#8449](https://github.com/osquery/osquery/pull/8449))
- Reduce scheduled builds amount ([#8457](https://github.com/osquery/osquery/pull/8457))

<a name="5.14.1"></a>
## [5.14.1](https://github.com/osquery/osquery/releases/tag/5.14.1)

[Git Commits](https://github.com/osquery/osquery/compare/5.13.1...5.14.1)

Representing commits from 13 contributors! Thank you all.

### Windows codesigning note

Starting with Osquery 5.14, we have changed our codesigning. Henceforth our releases will be signed by an osquery specific signing key issued by Microsoft Azure. 

### New Features

- Add `--yara_sigurl_authenticate` flag ([#8437](https://github.com/osquery/osquery/pull/8437))

### Table Changes

- Add additional WMI data to `deviceguard_status` table ([#8440](https://github.com/osquery/osquery/pull/8440))
- Fix linux `groups` table to handle larger group sets by increasing buffer size ([#8387](https://github.com/osquery/osquery/pull/8387))
- Add support for Firefox addons for snap installations ([#8374](https://github.com/osquery/osquery/pull/8374))
- Remove support for deprecated Safari Legacy Extensions ([#8426](https://github.com/osquery/osquery/pull/8426))
- macOS 15 `alf` support ([#8428](https://github.com/osquery/osquery/pull/8428))
- Update table `alf_explicit_auths` as not supported on macOS 15 ([#8435](https://github.com/osquery/osquery/pull/8435))
- Update table `alf_exceptions` to support macOS 15 ([#8434](https://github.com/osquery/osquery/pull/8434))
- Fix for `windows_crashes` missing information on user mode memory dumps ([#8394](https://github.com/osquery/osquery/pull/8394))
- Fix: `safari_extensions` not returning results ([#8427](https://github.com/osquery/osquery/pull/8427))
- Rename `hvci_status` to `deviceguard_status` to better reflect the data collected. ([#8390](https://github.com/osquery/osquery/pull/8390))

### Under the Hood improvements

- Add column optimization support to allow processing `IN` constraints all at once in xFilter ([#8263](https://github.com/osquery/osquery/pull/8263))
- Minor improvements to the hashing logic ([#8398](https://github.com/osquery/osquery/pull/8398))
- Refactor `readFile` ([#8410](https://github.com/osquery/osquery/pull/8410))

### Bug Fixes

- Fix `unified_log` handling of timestamp formats ([#8451](https://github.com/osquery/osquery/pull/8451))
- Fixes crash with non-null-terminated values in registry enumeration ([#8421](https://github.com/osquery/osquery/pull/8421))
- Fix: Check and free cert context creation in windows certificates table ([#8420](https://github.com/osquery/osquery/pull/8420))
- fix: Handle strftime potential error in the time table ([#8431](https://github.com/osquery/osquery/pull/8431))
- Fix crash in socket table parsing on windows ([#8419](https://github.com/osquery/osquery/pull/8419))

### Build

- Run tests on macos-15 ([#8430](https://github.com/osquery/osquery/pull/8430))
- Update tests for `unified_log` table to work around slowness ([#8450](https://github.com/osquery/osquery/pull/8450))
- tests: Ensure python http server is ready to serve ([#8452](https://github.com/osquery/osquery/pull/8452))
- Extend timeout for test HTTP server ([#8445](https://github.com/osquery/osquery/pull/8445))
- Upgrade GitHub Actions `upload-artifact` to v4 ([#8423](https://github.com/osquery/osquery/pull/8423))
- Boost 1.86 compatibility ([#8409](https://github.com/osquery/osquery/pull/8409))
- build: Cleanups and fixes for a newer clang toolchain ([#8412](https://github.com/osquery/osquery/pull/8412))
- ci: Update the upload-artifact action to v4.4.0 ([#8416](https://github.com/osquery/osquery/pull/8416))
- build: Silence deprecation warnings about non standard extensions on VS2022 ([#8405](https://github.com/osquery/osquery/pull/8405))
- Add missing includes causing compilation error with Clang 18.1.8 ([#8400](https://github.com/osquery/osquery/pull/8400))
- build(deps): bump actions/download-artifact from 2 to 4.1.7 in /.github/workflows ([#8411](https://github.com/osquery/osquery/pull/8411))

<a name="5.13.1"></a>
## [5.13.1](https://github.com/osquery/osquery/releases/tag/5.13.1)

[Git Commits](https://github.com/osquery/osquery/compare/5.12.2...5.13.1)

Representing commits from 21 contributors! Thank you all.

### Windows codesigning note

The Windows binaries and MSI package have been signed with the [Fleet Device Management](https://fleetdm.com) codesigning certificate as the osquery project is currently working on identity verification to get a new signing certificate.

### Table Changes

- The Python manifest directories, `.egg-info` and `.dist-info`, contain flat file hierarchies ([#8318](https://github.com/osquery/osquery/pull/8318))
- Table `users` on linux by default to return only users in `/etc/passwd` ([#8342](https://github.com/osquery/osquery/pull/8342))
- Add `sha256` hash to `apparmor_profiles` table ([#8345](https://github.com/osquery/osquery/pull/8345))
- Add support for metalink and store repo config file name in `yum_sources` table ([#8307](https://github.com/osquery/osquery/pull/8307))
- Update `user_ssh_keys` with additional details for OpenSSL-style keys ([#8314](https://github.com/osquery/osquery/pull/8314))
- Fix table `dns_resolvers` dns-search bug with multiple search domains ([#8329](https://github.com/osquery/osquery/pull/8329))
- Fix `process_open_sockets` to correctly displays `family` and `protocol` on macOS ([#8315](https://github.com/osquery/osquery/pull/8315))
- Add missing SSH key types to `authorized_keys` that support FIDO2 authentication ([#8319](https://github.com/osquery/osquery/pull/8319))

### Under the Hood improvements

- Improve error message when required constraint missing ([#8358](https://github.com/osquery/osquery/pull/8358))
- Add verbose logging when distributed requests fail and retry ([#8321](https://github.com/osquery/osquery/pull/8321))

### Bug Fixes

- Fix crash in `rpm_packages` table by upgrading librpm from 4.18.0 to 4.18.2 [#8388](https://github.com/osquery/osquery/pull/8388)
- Fix crash in linux file monitoring (related to NFS mounted directories) [#8392](https://github.com/osquery/osquery/pull/8392)
- Fix listDirectoriesInDirectory to check if symlinks point to directories (fixes `inotify` warnings flooded in logs) [#8399](https://github.com/osquery/osquery/pull/8399)
- Fix for Potential memory leak in class `ServiceArgumentParser`'s Constructor ([#8368](https://github.com/osquery/osquery/pull/8368))
- Fix for Crash in `ServiceArgumentParser` via `ServiceMain` ([#8353](https://github.com/osquery/osquery/pull/8353))
- Fixing real precision by limiting precision to 15 digits ([#8355](https://github.com/osquery/osquery/pull/8355) and [#8302](https://github.com/osquery/osquery/pull/8302))
- Fix invalid memory access in `curl_certificates` table ([#8339](https://github.com/osquery/osquery/pull/8339))
- Add pending state to ATC tables to avoid duplicate sql attaches ([#8324](https://github.com/osquery/osquery/pull/8324)) & revert ATC changes from ([#8233](https://github.com/osquery/osquery/pull/8233)) that caused a race condition and ATC table failure
- Fix crash when carve size is stored as string ([#8297](https://github.com/osquery/osquery/pull/8297))

### Documentation

- Updated Time Machine table documentation to require FDA ([#8325](https://github.com/osquery/osquery/pull/8325))
- Update `processes` table spec and docs, to remove outdated column alias ([#8363](https://github.com/osquery/osquery/pull/8363))
- Fill in missing column descriptions to spec for `device_partitions` ([#8364](https://github.com/osquery/osquery/pull/8364))
- Improve explanation of required columns ([#8365](https://github.com/osquery/osquery/pull/8365))
- Update `package_receipts` table example ([#8326](https://github.com/osquery/osquery/pull/8326))
- Remove some duplicated words from code comments and strings ([#8336](https://github.com/osquery/osquery/pull/8336))
- Update description for `alf_explicit_auths` [#8371](https://github.com/osquery/osquery/pull/8371)

### Build

- Correct spec file name to `macwin` ([#8311](https://github.com/osquery/osquery/pull/8311))
- Correct xz submodule url and openssl download url [#8383](https://github.com/osquery/osquery/pull/8383)
- Update Linux Docker image to Ubuntu 20.04 ([#8369](https://github.com/osquery/osquery/pull/8369))
- Fix util-linux submodule url ([#8303](https://github.com/osquery/osquery/pull/8303))
- Update macos builder to 14 and tester to 12 ([#8359](https://github.com/osquery/osquery/pull/8359))
- Make fallthrough explicit in `sqlite_encoding.cpp` ([#8361](https://github.com/osquery/osquery/pull/8361))
- Fix macOS python dependencies install step ([#8308](https://github.com/osquery/osquery/pull/8308))
- Bump `jinja2` from `3.1.3` to `3.1.4`. ([#8330](https://github.com/osquery/osquery/pull/8330))

<a name="5.12.2"></a>
## [5.12.2](https://github.com/osquery/osquery/releases/tag/5.12.2)

[Git Commits](https://github.com/osquery/osquery/compare/5.12.1...5.12.2)

This release is a hot fix. It reverts #8233, which had inadvertently broken ATC tables under some conditions.

Representing commits from 3 contributors! Thank you all.

### Bug Fixes

- Revert Don't add ATC table name to registry until after sqlite DB initialization #8233 ([#8334](https://github.com/osquery/osquery/pull/8334))

### Build

- CI: Fix macOS python dependencies install step ([#8308](https://github.com/osquery/osquery/pull/8308))

<a name="5.12.1"></a>
## [5.12.1](https://github.com/osquery/osquery/releases/tag/5.12.1)

[Git Commits](https://github.com/osquery/osquery/compare/5.11.0...5.12.1)

Representing commits from 11 contributors! Thank you all.

### New Features

- New flag `logger_tls_backoff_max` to configure the retry backoff for TLS logger plugin ([#8230](https://github.com/osquery/osquery/pull/8230))

### Table Changes

- Port the `battery` table to Windows ([#8267](https://github.com/osquery/osquery/pull/8267))
- Update `homebrew_packages` table to include Casks ([#8276](https://github.com/osquery/osquery/pull/8276))
- Update `cpu_info` to include `load_percentage` on windows ([#8275](https://github.com/osquery/osquery/pull/8275))
- Check path exists first in `vscode_extensions` ([#8292](https://github.com/osquery/osquery/pull/8292))
- `deb_packages` to ignore non existent admindirs ([#8288](https://github.com/osquery/osquery/pull/8288))
- Add missing path separator in Safari Extensions table generator ([#8273](https://github.com/osquery/osquery/pull/8273))
- Add windows UBR to `os_version` table ([#8265](https://github.com/osquery/osquery/pull/8265))

### Under the Hood improvements

- Persist query performance stats ([#8250](https://github.com/osquery/osquery/pull/8250))
- Deprecate `worker_threads` flag ([#8278](https://github.com/osquery/osquery/pull/8278))
- Change message from warning to error when extension could not be loaded ([#8260](https://github.com/osquery/osquery/pull/8260))
- Refactor macOS system profile report retrieval ([#8251](https://github.com/osquery/osquery/pull/8251))
- Clear performance stats when modifying scheduled/pack query ([#8239](https://github.com/osquery/osquery/pull/8239))

### Bug Fixes

- Fix version collate returning incorrect value when last character is a delimiter ([#8283](https://github.com/osquery/osquery/pull/8283))
- Fix a memory leak in `unified_log` ([#8274](https://github.com/osquery/osquery/pull/8274))
- Don't add ATC table name to registry until after sqlite DB initialization ([#8233](https://github.com/osquery/osquery/pull/8233))

### Documentation

- Update Jinja dependency for docs ([#8285](https://github.com/osquery/osquery/pull/8285))
- Remove Zercurity from fleet managers list ([#8293](https://github.com/osquery/osquery/pull/8293))
- Fix missing spaces in `kernel_keys` column descriptions ([#8289](https://github.com/osquery/osquery/pull/8289))
- Update description for amperage in battery table. ([#8253](https://github.com/osquery/osquery/pull/8253))

### Packs

- Fix packs to check for platform before including queries ([#7461](https://github.com/osquery/osquery/pull/7461))

### Build

- Downgrade sqlite to 3.42 to prevent a regression with required columns ([#8295](https://github.com/osquery/osquery/pull/8295))
- cve: Remove libxml2 dependency ([#8282](https://github.com/osquery/osquery/pull/8282))
- cve: Update libexpat to 2.6.0 ([#8281](https://github.com/osquery/osquery/pull/8281))
- cve: Update sqlite to 3.45.0 ([#8259](https://github.com/osquery/osquery/pull/8259))
- cve: Update openssl to 3.2.1 ([#8262](https://github.com/osquery/osquery/pull/8262))
- ci: Use all available cores and print more stats ([#8248](https://github.com/osquery/osquery/pull/8248))
- cmake: Pass the osquery python path to googletest ([#8237](https://github.com/osquery/osquery/pull/8237))
- test: Fix vscodeExtensions.test_sanity test ([#8236](https://github.com/osquery/osquery/pull/8236))
- cmake: Correct typo, semvar -> semver ([#8234](https://github.com/osquery/osquery/pull/8234))

<a name="5.11.0"></a>
## [5.11.0](https://github.com/osquery/osquery/releases/tag/5.11.0)

[Git Commits](https://github.com/osquery/osquery/compare/5.10.2...5.11.0)

Representing commits from 11 contributors! Thank you all.

### Table Changes

- Add new table `vscode_extensions` ([#8150](https://github.com/osquery/osquery/pull/8150))
- Add support for additional Apple Silicon columns in `secureboot` table ([#8215](https://github.com/osquery/osquery/pull/8215))
- Add Shortcut metadata parsing on Windows in the `file` table ([#8143](https://github.com/osquery/osquery/pull/8143))
- Remove `atom_packages` table ([#8181](https://github.com/osquery/osquery/pull/8181))
- Add additional chrome extensions paths ([#8170](https://github.com/osquery/osquery/pull/8170)) to pick up extensions for Chrome Beta, Chrome Dev, and Vivaldi.

### Under the Hood improvements

- Add version collations to column definitions ([#8222](https://github.com/osquery/osquery/pull/8222))
- Add support for additional collations in column definitions ([#8214](https://github.com/osquery/osquery/pull/8214))
- Add version collate functions ([#8168](https://github.com/osquery/osquery/pull/8168))
- Added cache and throttling for `certificates`, `keychain_acls`, and `keychain_items` tables ([#8192](https://github.com/osquery/osquery/pull/8192)). This is intended to reduce the occurrence of keychain corruption due to broken macOS APIs.
- process_open_sockets: Mark pid column as additional instead of index ([#8191](https://github.com/osquery/osquery/pull/8191))

### Bug Fixes

- Add stricter checks to JSON parsing ([#8229](https://github.com/osquery/osquery/pull/8229))
- Fix signed/unsigned mismatch in powershell_events ([#8225](https://github.com/osquery/osquery/pull/8225))
- Fix a crash in firefox_addons ([#8227](https://github.com/osquery/osquery/pull/8227))
- Correct the aws_sts_region behavior ([#8184](https://github.com/osquery/osquery/pull/8184))

### Documentation

- Update building.md prereqs for Windows ([#8216](https://github.com/osquery/osquery/pull/8216))
- Correct link to a PR in the 4.7.0 changelog ([#8186](https://github.com/osquery/osquery/pull/8186))
- Call out in the CHANGELOG the format changes of the status logs decorations ([#8174](https://github.com/osquery/osquery/pull/8174))
- Remove some duplicated lines from 5.8.1 changelog ([#8172](https://github.com/osquery/osquery/pull/8172))
- Fix typo in table specs ([#8163](https://github.com/osquery/osquery/pull/8163))
- Keychain cache and throttling documentation. ([#8205](https://github.com/osquery/osquery/pull/8205))
- Changelog 5.10.2 ([#8171](https://github.com/osquery/osquery/pull/8171))


### Build / Dependencies

- Update libxml2 to v2.12.3 ([#8223](https://github.com/osquery/osquery/pull/8223))
- Update zlib to 1.3 and ignore a CVE ([#8218](https://github.com/osquery/osquery/pull/8218))
- Update openssl to 3.2.0 ([#8212](https://github.com/osquery/osquery/pull/8212))
- Update nvdlib to use the latest NVD APIs ([#8207](https://github.com/osquery/osquery/pull/8207))
- Fix Linux build ([#8208](https://github.com/osquery/osquery/pull/8208))
- Correct job order ([#8185](https://github.com/osquery/osquery/pull/8185))
- Re-enable tools_tests_testrelease ([#8221](https://github.com/osquery/osquery/pull/8221))
- Enable client certificate verification in the TLS tests ([#8211](https://github.com/osquery/osquery/pull/8211))
- Temporary workaround to build with XCode 15 ([#8197](https://github.com/osquery/osquery/pull/8197))


<a name="5.10.2"></a>
## [5.10.2](https://github.com/osquery/osquery/releases/tag/5.10.2)

[Git Commits](https://github.com/osquery/osquery/compare/5.9.1...5.10.2)

This release has several updates and bugfixes. Several improvements to various tables, and their handling.

One potential breaking change, is in how [the watchdog calculates CPU utilization](https://github.com/osquery/osquery/pull/8104).
Previously, this calculation was based on physical CPUs, now it is based on virtual cores. We believe this makes more sense with modern CPUs.

A second potential breaking change, is in PR [#8102](https://github.com/osquery/osquery/pull/8102). In addition to allowing decorations to the top level of the status logs, this PR normalizes the decorations format to the results log. In practice, this means that the `unixTime`, `severity` and `line` JSON fields are now numbers instead of strings.

Representing commits from 18 contributors! Thank you all.

### New Features

- Add `--enable_watchdog_debug` flag and improve watchdog error messages ([#8070](https://github.com/osquery/osquery/pull/8070))
- Add `--aws_enforce_fips` to enforce AWS FIPS endpoints ([#8075](https://github.com/osquery/osquery/pull/8075))
- Add new AWS valid regions ([#8110](https://github.com/osquery/osquery/pull/8110))
- Implement `decorations_top_level` flag for status logs ([#8102](https://github.com/osquery/osquery/pull/8102))

### Table Changes

- Add new macOS SIP config flags ([#8101](https://github.com/osquery/osquery/pull/8101))
- Added `cloud`_id to `ycloud_instance_metadata` - the vm metadata table for Yandex Cloud ([#8086](https://github.com/osquery/osquery/pull/8086))
- Allow querying of kernel and filesystem drivers ([#8119](https://github.com/osquery/osquery/pull/8119))
- Update `es_process_file_events` adding support for open events, and for only triggering on `file_paths` ([#8114](https://github.com/osquery/osquery/pull/8114))
- Update `firefox_addons` to use rapidjson to parse and don't block on read ([#8089](https://github.com/osquery/osquery/pull/8089))
- Update macOS `es_process_events` table: quote spaces in command line and environment variables ([#8054](https://github.com/osquery/osquery/pull/8054))
- Update linux `disk_encryption` to recursively query parent crypt status ([#8052](https://github.com/osquery/osquery/pull/8052))
- Add, and revert, indexing on `block_devices` ([#8037](https://github.com/osquery/osquery/pull/8037), [#8151](https://github.com/osquery/osquery/pull/8151))

### Under the Hood improvements

- Add warnings when an enrollment secret cannot be found ([#8082](https://github.com/osquery/osquery/pull/8082))
- Avoid blocking when reading plist files ([#8099](https://github.com/osquery/osquery/pull/8099))
- Fix named virtual table create statement ([#8139](https://github.com/osquery/osquery/pull/8139))
- Remove forensicReadFile ([#8085](https://github.com/osquery/osquery/pull/8085))
- Substitute the TEXT macro with SQL_TEXT in table code ([#8091](https://github.com/osquery/osquery/pull/8091))
- Use JSON member iterator instead of rescanning ([#8122](https://github.com/osquery/osquery/pull/8122))
- core: Avoid checking if a file exists before opening ([#8087](https://github.com/osquery/osquery/pull/8087))
- improvement: Avoid unnecessary string conversions ([#8093](https://github.com/osquery/osquery/pull/8093))
- watchdog: Use virtual cores to calculate CPU utilization limit ([#8104](https://github.com/osquery/osquery/pull/8104))

### Bug Fixes

- Always lock event_index_mutex when accessing event_index map ([#8077](https://github.com/osquery/osquery/pull/8077))
- Check audit return values with <= ([#8125](https://github.com/osquery/osquery/pull/8125))
- Fix `wifi_survey` table not to crash if the ssid cannot be retrieved ([#8153](https://github.com/osquery/osquery/pull/8153))
- Fix macOS EndpointSecurity FIM mute inversion for file paths ([#8166](https://github.com/osquery/osquery/pull/8166))

### Documentation

- Add a list of Osquery fleet managers ([#7781](https://github.com/osquery/osquery/pull/7781))
- Add basic file carving documentation ([#8118](https://github.com/osquery/osquery/pull/8118))
- Changelog for 5.9.1 ([#8088](https://github.com/osquery/osquery/pull/8088))
- Changelog 5.10.1 ([#8155](https://github.com/osquery/osquery/pull/8155))
- Fixed small doc error ([#8147](https://github.com/osquery/osquery/pull/8147))
- Update Automatic Table Construction example ([#8094](https://github.com/osquery/osquery/pull/8094))
- Update XCode version mentions to the proper one ([#8128](https://github.com/osquery/osquery/pull/8128))
- Update the description of `serial_number` in `connected_displays` ([#8113](https://github.com/osquery/osquery/pull/8113))

### Build

- Fix openssl build arch for Windows ARM64 ([#8134](https://github.com/osquery/osquery/pull/8134))
- Fix python test http server use `SSLContext.wrap_socket()` instead of deprecated `ssl.wrap_socket()` ([#8169](https://github.com/osquery/osquery/pull/8169))
- GitHub Action to cleanup at stale ec2 runners ([#8156](https://github.com/osquery/osquery/pull/8156))
- Ignore CVE-2023-30571 ([#8065](https://github.com/osquery/osquery/pull/8065))
- Missing pragma/header guard for boottime.h ([#8117](https://github.com/osquery/osquery/pull/8117))
- Permit cross compiling for x86_64 on Apple Silicon ([#8136](https://github.com/osquery/osquery/pull/8136))
- build: update macos hosted github runner to macos-12 monterey ([#8100](https://github.com/osquery/osquery/pull/8100))
- ci: Fix DistributedTests.test_run_queries_with_denylisted_query test ([#8154](https://github.com/osquery/osquery/pull/8154))
- ci: Increase aarch64 available space by splitting the build ([#8131](https://github.com/osquery/osquery/pull/8131))
- ci: Increase disk space on the Linux x86_64 runner ([#8133](https://github.com/osquery/osquery/pull/8133))
- ci: Remove flakyness when removing unused packages on Linux ([#8144](https://github.com/osquery/osquery/pull/8144))
- cve: Fix the expat product name in the libraries manifest ([#8158](https://github.com/osquery/osquery/pull/8158))
- cve: Ignore dbus CVE-2023-34969 ([#8126](https://github.com/osquery/osquery/pull/8126))
- cve: Ignore libcap CVE-2023-2603 ([#8127](https://github.com/osquery/osquery/pull/8127))
- cve: Update expat to version 2.5.0 ([#8159](https://github.com/osquery/osquery/pull/8159))
- cve: Update libmagic to 5.45 ([#8142](https://github.com/osquery/osquery/pull/8142))
- cve: Update lzma to 5.4.4 ([#8135](https://github.com/osquery/osquery/pull/8135))
- cve: Update openssl to 3.1.3 ([#8141](https://github.com/osquery/osquery/pull/8141))
- libs: Fix openssl build on aarch64 ([#8084](https://github.com/osquery/osquery/pull/8084))
- libs: Update openssl to 3.1.1 ([#8081](https://github.com/osquery/osquery/pull/8081))
- libs: Update openssl to 3.1.2 ([#8124](https://github.com/osquery/osquery/pull/8124))
- test: Fix leaks in inotify and rocksdb tests ([#8080](https://github.com/osquery/osquery/pull/8080))


<a name="5.9.1"></a>
## [5.9.1](https://github.com/osquery/osquery/releases/tag/5.9.1)

[Git Commits](https://github.com/osquery/osquery/compare/5.8.2...5.9.1)

Big shoutout for the Windows Arm port!

Representing commits from 14 contributors! Thank you all.

### New Features

- Add support for Windows on Arm ([#7918](https://github.com/osquery/osquery/pull/7918))
- logger: Add new `string_batch` request type to compliment existing `string` type ([#8027](https://github.com/osquery/osquery/pull/8027))

### Table Changes

- Add `connected_displays` table on macOS ([#7946](https://github.com/osquery/osquery/pull/7946))
- Add `windows_search` table ([#7990](https://github.com/osquery/osquery/pull/7990))
- Restore functionality of `crashes` table on macOS 12 and newer ([#7819](https://github.com/osquery/osquery/pull/7819))
- Update `keychain_items` to include data about key types ([#8002](https://github.com/osquery/osquery/pull/8002))
- Update `os_version` to include Apple RSR fields using native API ([#8011](https://github.com/osquery/osquery/pull/8011))
- Update `safari_extensions` to handle the current app extensions pattern ([#7991](https://github.com/osquery/osquery/pull/7991))
- Update `system_info` to include the nnumber of sockets ([#8038](https://github.com/osquery/osquery/pull/8038))
- Update `unified_log` table to add `predicate` column and optimize timestamp constraint ([#8019](https://github.com/osquery/osquery/pull/8019))

### Under the Hood improvements

- Improving `listDirectoriesInDirectory` by using `std::fs` ([#7974](https://github.com/osquery/osquery/pull/7974))
- Do not consider a 404 as an error in ec2-instance-metadata ([#8025](https://github.com/osquery/osquery/pull/8025))
- Release objects and free memory obtained from COM ([#7999](https://github.com/osquery/osquery/pull/7999))
- Do not pass wstring::c_str() to wstringToString function ([#8000](https://github.com/osquery/osquery/pull/8000))
- Do not copy process arguments into vector for CreateProcess call ([#7956](https://github.com/osquery/osquery/pull/7956))

### Bug Fixes

- Fix `version` column in `homebrew_packages` ([#8057](https://github.com/osquery/osquery/pull/8057))
- Improve extended_attributes implementation for Linux and macOS ([#8046](https://github.com/osquery/osquery/pull/8046))
- Update event tables to mark time column as "additional" ([#8020](https://github.com/osquery/osquery/pull/8020))

### Documentation

- Update expired Slack invite ([#8051](https://github.com/osquery/osquery/pull/8051))
- Update `es_process_file_events.table` description ([#7978](https://github.com/osquery/osquery/pull/7978))
- CHANGELOG 5.8.2 ([#7986](https://github.com/osquery/osquery/pull/7986))

### Build

- cve: Update to openssl 1.1.1u ([#8050](https://github.com/osquery/osquery/pull/8050))
- cmake: Add an option to disable shallow git clone operations ([#8026](https://github.com/osquery/osquery/pull/8026))
- Fix the aarch64 workflow ([#8036](https://github.com/osquery/osquery/pull/8036))
- test: Fix a leak in ExtendedAttributesTableTests SetUp function ([#8045](https://github.com/osquery/osquery/pull/8045))
- cve: Update libxml2 to v2.11.2 ([#8023](https://github.com/osquery/osquery/pull/8023))
- libs: Bring out LZ4 from rdkafka and update it to v1.9.4 ([#7996](https://github.com/osquery/osquery/pull/7996))
- ci: Update python version and docs build tools ([#7969](https://github.com/osquery/osquery/pull/7969))
- ci: Update aarch64 runner to Ubuntu 20.04 and update badges ([#7984](https://github.com/osquery/osquery/pull/7984))
- Add few unit tests for the hashing component ([#7993](https://github.com/osquery/osquery/pull/7993))


<a name="5.8.2"></a>
## [5.8.2](https://github.com/osquery/osquery/releases/tag/5.8.2)

[Git Commits](https://github.com/osquery/osquery/compare/5.8.1...5.8.2)

Representing commits from 6 contributors! Thank you all.


### Bug Fixes

- Fix empty batch result set reporting ([#7958](https://github.com/osquery/osquery/pull/7958))
- Fix COM security initialization  by setting COM security per interface level ([#7963](https://github.com/osquery/osquery/pull/7963))
- Fix username field in managed_policy table ([#7944](https://github.com/osquery/osquery/pull/7944))

### Documentation

- CHANGELOG 5.8.1 ([#7957](https://github.com/osquery/osquery/pull/7957))

### Build

- test: Do not always expect a row from the secureboot table ([#7967](https://github.com/osquery/osquery/pull/7967))
- cmake: Only link against the experiments loader when needed ([#7959](https://github.com/osquery/osquery/pull/7959))
- tests: Fix some tests becoming osquery shells ([#7964](https://github.com/osquery/osquery/pull/7964))
- test: Fix SystemdUnitsTest missing the unit_file_state column ([#7965](https://github.com/osquery/osquery/pull/7965))
- tests: Do not always build root tests on Linux ([#7966](https://github.com/osquery/osquery/pull/7966))


<a name="5.8.1"></a>
## [5.8.1](https://github.com/osquery/osquery/releases/tag/5.8.1)

[Git Commits](https://github.com/osquery/osquery/compare/5.7.0...5.8.1)

Representing commits from 22 contributors! Thank you all.

### New Features

- Record and send statistics for distributed queries ([#7870](https://github.com/osquery/osquery/pull/7870))

### Table Changes

- Add ETW-based process events table for Windows ([#7821](https://github.com/osquery/osquery/pull/7821))
- Add `pid_with_namespace` for `yara` table ([#7920](https://github.com/osquery/osquery/pull/7920))
- Add a new table `kernel_keys` to the Linux platform ([#7876](https://github.com/osquery/osquery/pull/7876))
- Leave `min_version` empty in `xprotect_meta` when not specified ([#7926](https://github.com/osquery/osquery/pull/7926))
- Port the `secureboot` table to macOS ([#7692](https://github.com/osquery/osquery/pull/7692))
- Update `docker_container_stats` table to include `cached_memory` column ([#7807](https://github.com/osquery/osquery/pull/7807))
- `cpu_info`: Port the table to macOS x86 and Apple Silicon ([#7757](https://github.com/osquery/osquery/pull/7757))
- experiments: Implement a new `bpf_process_events_v2` table ([#7773](https://github.com/osquery/osquery/pull/7773))
- `systemd_units`: Add new `unit_file_state` column ([#7895](https://github.com/osquery/osquery/pull/7895))

### Under the Hood improvements

- Set counter consistently so zero always indicates all records ([#7801](https://github.com/osquery/osquery/pull/7801))
- Support logging empty result set in batch format for initial runs ([#7803](https://github.com/osquery/osquery/pull/7803))
- Support rollbacks of osquery when new versions introduce new column families ([#7712](https://github.com/osquery/osquery/pull/7712))
- analysis.py: Add --pack flag to load queries from a pack file ([#7935](https://github.com/osquery/osquery/pull/7935))
- profile.py: Log # of queries loaded and raise an error if 0 are loaded ([#7934](https://github.com/osquery/osquery/pull/7934))

### Bug Fixes

- Clear cached constraints and columns in xBestIndex ([#7435](https://github.com/osquery/osquery/pull/7435))
- Fix assert fail for unverified WMI request result ([#7921](https://github.com/osquery/osquery/pull/7921))
- Fix leaks in `scheduled_tasks` (#7903) ([#7904](https://github.com/osquery/osquery/pull/7904))
- Flush console buffer during ungraceful exit ([#7829](https://github.com/osquery/osquery/pull/7829))
- Propagate windows errors to the exit code ([#7896](https://github.com/osquery/osquery/pull/7896))
- Relax osquery safe permissions check ([#7763](https://github.com/osquery/osquery/pull/7763))
- Silence warnings for more builtin Chrome and Brave extensions ([#7932](https://github.com/osquery/osquery/pull/7932))
- Workaround for hung `routes` table ([#7916](https://github.com/osquery/osquery/pull/7916))
- dns_resolvers: fix typo in the name when spawning in namespace ([#7875](https://github.com/osquery/osquery/pull/7875))
- test: Fix flaky test_daemon_sigint ([#7888](https://github.com/osquery/osquery/pull/7888))

### Documentation

- Add note about `windows_security_products` compatibility ([#7880](https://github.com/osquery/osquery/pull/7880))
- CHANGELOG 5.7.0 ([#7894](https://github.com/osquery/osquery/pull/7894))
- Docs: mention the recent adoption of automatic CVE scanning ([#7878](https://github.com/osquery/osquery/pull/7878))
- Fix broken link in CODE_OF_CONDUCT.md ([#7922](https://github.com/osquery/osquery/pull/7922))
- docs: Update the list of pages ([#7866](https://github.com/osquery/osquery/pull/7866))
- docs: clarify that logger_plugin is set from CLI ([#7917](https://github.com/osquery/osquery/pull/7917))

### Build

- Do not catch table or registry exceptions when running tests ([#7621](https://github.com/osquery/osquery/pull/7621))
- Fix and document discovery queries behavior on distributed queries and add tests ([#7655](https://github.com/osquery/osquery/pull/7655))
- Try to free some disk space on the arm64 runners ([#7950](https://github.com/osquery/osquery/pull/7950))
- ci: Automatically cancel old PR jobs ([#7887](https://github.com/osquery/osquery/pull/7887))
- ci: Improve error message when a library is missing from the manifest ([#7899](https://github.com/osquery/osquery/pull/7899))
- ci: Remove Windows 32bit build ([#7939](https://github.com/osquery/osquery/pull/7939))
- ci: Update some actions to remove deprecation warnings ([#7864](https://github.com/osquery/osquery/pull/7864))
- ci: Workaround in the aarch64 runner to avoid out of space ([#7941](https://github.com/osquery/osquery/pull/7941))
- cmake: Remove forced static libraries search for osquery-toolchain ([#7881](https://github.com/osquery/osquery/pull/7881))
- cve: Ignore libcryptsetup cves ([#7871](https://github.com/osquery/osquery/pull/7871))
- cve: Ignore libdpkg CVE-2022-1664 ([#7872](https://github.com/osquery/osquery/pull/7872))
- cve: Ignore libgcrypt cves ([#7873](https://github.com/osquery/osquery/pull/7873))
- cve: Ignore sqlite CVE-2022-46908 ([#7911](https://github.com/osquery/osquery/pull/7911))
- cve: Ignore util-linux cves ([#7929](https://github.com/osquery/osquery/pull/7929))
- cve: Update librpm to 4.18.0 ([#7910](https://github.com/osquery/osquery/pull/7910))
- cve: Update openssl to 1.1.1t ([#7937](https://github.com/osquery/osquery/pull/7937))
- cve: Update yara to 4.2.3 ([#7912](https://github.com/osquery/osquery/pull/7912))
- git: Ignore compile_commands.json and pyrightconfig.json ([#7885](https://github.com/osquery/osquery/pull/7885))
- libs: Fix libmagic build on macOS ([#7915](https://github.com/osquery/osquery/pull/7915))
- libs: Fix system paths used by dbus ([#7919](https://github.com/osquery/osquery/pull/7919))
- libs: Update dbus to 1.12.24 ([#7905](https://github.com/osquery/osquery/pull/7905))
- libs: Update libarchive to 3.6.2 ([#7877](https://github.com/osquery/osquery/pull/7877))
- libs: Update libxml2 to 2.10.3 ([#7882](https://github.com/osquery/osquery/pull/7882))
- libs: Update popt to 1.19 ([#7909](https://github.com/osquery/osquery/pull/7909))
- libs: Update util-linux to 2.35.2 ([#7902](https://github.com/osquery/osquery/pull/7902))
- libs: Update zlib to 1.2.13 ([#7874](https://github.com/osquery/osquery/pull/7874))
- libs: update Thrift to 0.17 ([#7868](https://github.com/osquery/osquery/pull/7868))
- test: Add an option to run only selected python testcases ([#7890](https://github.com/osquery/osquery/pull/7890))
- test: Speed up ec2InstanceMetadata.test_sanity ([#7907](https://github.com/osquery/osquery/pull/7907))


<a name="5.7.0"></a>
## [5.7.0](https://github.com/osquery/osquery/releases/tag/5.7.0)

[Git Commits](https://github.com/osquery/osquery/compare/5.6.0...5.7.0)

Representing commits from 12 contributors! Thank you all.

### CVEs

Addressed by updating a library:

Ignored due to not affecting osquery:
  - libzstd CVE-2021-24031 via ([#7865](https://github.com/osquery/osquery/pull/7865))

### New Features

- New table `security_profile_info` to retrieve security profile information on Windows ([#7794](https://github.com/osquery/osquery/pull/7794))

### Table Changes

- Add column to `es_process_events` for process codesigning flags ([#7726](https://github.com/osquery/osquery/pull/7726))
- `shimcache`: Only check CurrentControlSet to avoid duplicate rows ([#7832](https://github.com/osquery/osquery/pull/7832))
- `processes`: Fix the procfs memory unit kB, which is 1024 bytes not 1000 ([#7818](https://github.com/osquery/osquery/pull/7818))
- Fix permissions on opening pipes for reading in `pipes` table ([#7810](https://github.com/osquery/osquery/pull/7810))
- Fix the empty `host` column from `logged_in_users` table ([#7685](https://github.com/osquery/osquery/pull/7685))
- `docker_containers`: Don't report `finished_at` for a container which is still running ([#7783](https://github.com/osquery/osquery/pull/7783))
- `processes`: Stabilize the `start_time` column value on macOS and Linux ([#7788](https://github.com/osquery/osquery/pull/7788))

### Bug Fixes

- Do not access the AWS SDK request content type if missing ([#7834](https://github.com/osquery/osquery/pull/7834))
- Fix deadlock when logging happens during a database reset ([#7798](https://github.com/osquery/osquery/pull/7798))
- Fix handling of some errors during an AWS HTTP request ([#7811](https://github.com/osquery/osquery/pull/7811))

### Documentation

- CHANGELOG 5.6.0 ([#7804](https://github.com/osquery/osquery/pull/7804))
- Add link to official YARA docs ([#7792](https://github.com/osquery/osquery/pull/7792))
- Fix typo in `keychain_items` ([#7790](https://github.com/osquery/osquery/pull/7790))

### Packs

- packs/incident_response: `process_memory_map` is also applicable to Darwin ([#7789](https://github.com/osquery/osquery/pull/7789))

### Build

- cve: Ignore zstd CVE-2021-24031 ([#7865](https://github.com/osquery/osquery/pull/7865))
- ci: Add a job and helper scripts to periodically scan for CVEs ([#7787](https://github.com/osquery/osquery/pull/7787))
- ci: Update how we set github workflow step outputs ([#7791](https://github.com/osquery/osquery/pull/7791))
- ci: Fix python version when installing modules and testing on macos ([#7813](https://github.com/osquery/osquery/pull/7813))

<a name="5.6.0"></a>
## [5.6.0](https://github.com/osquery/osquery/releases/tag/5.6.0)

[Git Commits](https://github.com/osquery/osquery/compare/5.5.1...5.6.0)

Representing commits from 10 contributors! Thank you all.

### Table Changes

- Add `firmware_type` column to `platform_info` on macOS ([#7727](https://github.com/osquery/osquery/pull/7727))
- Add additional vendor support for the windows `wmi_bios_info` table ([#7631](https://github.com/osquery/osquery/pull/7631))
- Fix `docker_container_processes` on macOS ([#7746](https://github.com/osquery/osquery/pull/7746))
- Fix `process_file_events` subscriber being incorrectly initialized ([#7759](https://github.com/osquery/osquery/pull/7759))
- Fix `secureboot` on windows by acquire the necessary process privileges ([#7743](https://github.com/osquery/osquery/pull/7743))
- Improve macOS `mdfind` -- Reduce table overhead and support interruption ([#7738](https://github.com/osquery/osquery/pull/7738))
- Remove `binary` column from `firefox_addons` table ([#7735](https://github.com/osquery/osquery/pull/7735))
- Remove `is_running` column from macOS `running_apps` table ([#7774](https://github.com/osquery/osquery/pull/7774))

### Under the Hood improvements

- Add `notes` field to the schema and associated json ([#7747](https://github.com/osquery/osquery/pull/7747))
- Add extended platforms to the schema and associated json ([#7760](https://github.com/osquery/osquery/pull/7760))
- Fix a leak and improve users and groups APIs on Windows ([#7755](https://github.com/osquery/osquery/pull/7755))
- Have `--tls_dump` output body to `stderr` ([#7715](https://github.com/osquery/osquery/pull/7715))
- Improvements to osquery AWS logic ([#7714](https://github.com/osquery/osquery/pull/7714))
- Remove leftover FreeBSD related code and documentation ([#7739](https://github.com/osquery/osquery/pull/7739))

### Documentation

- CHANGELOG 5.5.1 ([#7737](https://github.com/osquery/osquery/pull/7737))
- Correct the description on how to configure and use Yara signature urls ([#7769](https://github.com/osquery/osquery/pull/7769))
- Document difference between `yara` and `yara_events` ([#7744](https://github.com/osquery/osquery/pull/7744))
- Link to the slack archives ([#7786](https://github.com/osquery/osquery/pull/7786))
- Update docs: `_changes` tables are not evented ([#7762](https://github.com/osquery/osquery/pull/7762))

### Build

- Delete temporary CTest files ([#7782](https://github.com/osquery/osquery/pull/7782))
- Fix table tests for macOS `running_apps` ([#7775](https://github.com/osquery/osquery/pull/7775))
- Fix table tests for windows `platform_info` ([#7742](https://github.com/osquery/osquery/pull/7742))
- Migrate jobs from ubuntu-18.04 to ubuntu-20.04 ([#7745](https://github.com/osquery/osquery/pull/7745))
- Remove unused find_packages modules and submodule ([#7771](https://github.com/osquery/osquery/pull/7771))

<a name="5.5.1"></a>
## [5.5.1](https://github.com/osquery/osquery/releases/tag/5.5.1)

[Git Commits](https://github.com/osquery/osquery/compare/5.4.0...5.5.1)

Osquery 5.5.1 has some really exciting table updates! There is a much
anticipated `unified_log` for macOS, this table is the replacement for
`asl`, and uses the current Apple APIs. Additionally, several tables
have improved their cross-platform support.

Representing commits from 14 contributors! Thank you all.

### New Features

- Add denylist mechanism to distributed queries ([#7675](https://github.com/osquery/osquery/pull/7675))

### Table Changes

- Add `cgroup_path` column to `processes` table on Linux ([#7728](https://github.com/osquery/osquery/pull/7728))
- Add `firmware_type` column to `platform_info` table on Windows. ([#7710](https://github.com/osquery/osquery/pull/7710))
- Add `unified_log` table for macOS (UAL) ([#7598](https://github.com/osquery/osquery/pull/7598), [#7713](https://github.com/osquery/osquery/pull/7713))
- Port `memory_devices` table to Windows ([#7633](https://github.com/osquery/osquery/pull/7633))
- Port `platform_info` table to M1 Macs ([#7660](https://github.com/osquery/osquery/pull/7660))
- Restore macOS `kernel_panics` table on modern macOS ([#7585](https://github.com/osquery/osquery/pull/7585))
- Update `battery` table on macOS m1 with correct raw battery max and current capacity ([#7721](https://github.com/osquery/osquery/pull/7721))
- Update `mdfind` query timeout to 30 seconds ([#7725](https://github.com/osquery/osquery/pull/7725))
- Update macos `password_policy` table to use use `-1` as sentinel value for `uid` column ([#7699](https://github.com/osquery/osquery/pull/7699))
- Update parsing of `authorized_keys` file  ([#7560](https://github.com/osquery/osquery/pull/7560))
- Update the `registry` table to be case insensitive for `key` ([#7708](https://github.com/osquery/osquery/pull/7708))


### Under the Hood improvements

- Add a mechanism to reduce memory retained on Linux ([#7502](https://github.com/osquery/osquery/pull/7502))
- Add denylist mechanism to distributed queries ([#7675](https://github.com/osquery/osquery/pull/7675))
- Add table spec support for `COLLATE NOCASE` ([#7680](https://github.com/osquery/osquery/pull/7680))
- Improve Pidfile handling ([#7304](https://github.com/osquery/osquery/pull/7304))
- Prevent the audit event system from using too much memory ([#7329](https://github.com/osquery/osquery/pull/7329))
- carves: use full pathnames while creating an archive ([#7681](https://github.com/osquery/osquery/pull/7681))

### Bug Fixes

- Fix `GetMemorySize` for Windows `memory_devices` table ([#7711](https://github.com/osquery/osquery/pull/7711))
- Fix `tpm_info` bug where values were out of date ([#7686](https://github.com/osquery/osquery/pull/7686))
- Fix a crash when parsing ATC config with no columns ([#7693](https://github.com/osquery/osquery/pull/7693))
- Fix bug in GetHomeDirectories filesystem function ([#7705](https://github.com/osquery/osquery/pull/7705))

### Documentation

- Add core to the type column description of osquery_extensions schema ([#7716](https://github.com/osquery/osquery/pull/7716))
- Add documentation about 3rd-party dependency security ([#7684](https://github.com/osquery/osquery/pull/7684))
- Add example for hostname form in `curl_certificate` table ([#7706](https://github.com/osquery/osquery/pull/7706))
- Adds info on how to use GTEST_FILTER on windows ([#7696](https://github.com/osquery/osquery/pull/7696))
- Changelog 5.4.0 ([#7678](https://github.com/osquery/osquery/pull/7678))
- Describe user-context-related caveat for screenlock table ([#7649](https://github.com/osquery/osquery/pull/7649))
- Update schema for `process_open_sockets.state` ([#7733](https://github.com/osquery/osquery/pull/7733))
- Update schema to reflect `platform_info` columns not available in Windows ([#7732](https://github.com/osquery/osquery/pull/7732))

### Build

- Add validation integration test for memory_devices ([#7722](https://github.com/osquery/osquery/pull/7722))
- Temporarily disable memory_devices integration test ([#7717](https://github.com/osquery/osquery/pull/7717))
- Update minimum macOS support from 10.12 to 10.14 ([#7707](https://github.com/osquery/osquery/pull/7707))
- ci: Update and temporarily disable the macOS Catalina test job ([#7700](https://github.com/osquery/osquery/pull/7700))
- cmake: Prevent defining some Linux only targets on other platforms ([#7672](https://github.com/osquery/osquery/pull/7672))
- libs: Update libxml2 to v2.9.14 ([#7729](https://github.com/osquery/osquery/pull/7729))
- libs: Update sqlite to version 3.39.2 ([#7736](https://github.com/osquery/osquery/pull/7736))
- test: Fix Mdfind.test_sanity flakyness ([#7701](https://github.com/osquery/osquery/pull/7701))

<a name="5.4.0"></a>
## [5.4.0](https://github.com/osquery/osquery/releases/tag/5.4.0)

[Git Commits](https://github.com/osquery/osquery/compare/5.3.0...5.4.0)

Representing commits from 15 contributors! Thank you all.

### New Features

- We're extending macOS Endpoint Security to include File Integrity monitoring. Check out the new `es_process_file_events` table. ([#7579](https://github.com/osquery/osquery/pull/7579))
- Add Docker build scripts and configuration ([#7619](https://github.com/osquery/osquery/pull/7619))

### Deprecation Notices

- Prevent CLI_FLAGs to be set via config ([#7561](https://github.com/osquery/osquery/pull/7561))
- Remove the `lldp_neighbors` table ([#7664](https://github.com/osquery/osquery/pull/7664))

### Table Changes

- New Table: `es_process_file_events` for macOS Endpoint Security based FIM ([#7579](https://github.com/osquery/osquery/pull/7579))
- New Table: `password_policy` table for macOS ([#7594](https://github.com/osquery/osquery/pull/7594))
- New Table: `windows_update_history` ([#7407](https://github.com/osquery/osquery/pull/7407))
- Add `memory_available` to linux `memory_info` table ([#7669](https://github.com/osquery/osquery/pull/7669))
- Port the `cpu_info` table to linux  ([#7499](https://github.com/osquery/osquery/pull/7499))
- Remove the `lldp_neighbors` table ([#7664](https://github.com/osquery/osquery/pull/7664))
- Update `deb_packages` table to not sisplay arch info in the package name ([#7638](https://github.com/osquery/osquery/pull/7638))
- Update `hardware_model` in the `system_info` table on Apple M1 machines to report correctly ([#7662](https://github.com/osquery/osquery/pull/7662))
- Update `shared_resources` table to add type names, fix type/maximum_allowed handling ([#7645](https://github.com/osquery/osquery/pull/7645))

### Under the Hood improvements

- Expand env vars before trying to enumerate crashes in `windows_crashes` table ([#7391](https://github.com/osquery/osquery/pull/7391))
- Implement a split and trim function using std::string_view ([#7636](https://github.com/osquery/osquery/pull/7636))
- Improve scheduled query denylisting and scheduler shutdown ([#7492](https://github.com/osquery/osquery/pull/7492))
- Prevent CLI_FLAGs to be set via config ([#7561](https://github.com/osquery/osquery/pull/7561))
- Remove unnecessary string copy ([#7625](https://github.com/osquery/osquery/pull/7625))

### Bug Fixes

- Add linwin to list of supported PLATFORM_DIRS ([#7646](https://github.com/osquery/osquery/pull/7646))
- Fix AWS certificate verification failing on all services  ([#7652](https://github.com/osquery/osquery/pull/7652))
- Fix MBCS support on Windows ([#7593](https://github.com/osquery/osquery/pull/7593))
- Fix `local_timezone` column in the `time` table on Windows ([#7656](https://github.com/osquery/osquery/pull/7656))
- Fix `system_info` table to support unicode on Windows ([#7626](https://github.com/osquery/osquery/pull/7626))
- Fix multiple Yara leaks ([#7615](https://github.com/osquery/osquery/pull/7615))
- Fix std::bad_alloc on pci_devices on Apple Silicon macs ([#7648](https://github.com/osquery/osquery/pull/7648))
- Fix tables spec files to specify `linux` and not `posix` ([#7644](https://github.com/osquery/osquery/pull/7644))
- Fix thrift server shutting down when dropping privileges ([#7639](https://github.com/osquery/osquery/pull/7639))

### Documentation

- CHANGELOG 5.3.0 ([#7575](https://github.com/osquery/osquery/pull/7575))
- Exclude `spec/example.table` when generating documentation ([#7647](https://github.com/osquery/osquery/pull/7647))
- Fix a UUID typo in the `disk_encryption` table ([#7608](https://github.com/osquery/osquery/pull/7608))
- Fix spelling of the word "owned" ([#7630](https://github.com/osquery/osquery/pull/7630))
- Fix typo in FIM docs for Windows ([#7676](https://github.com/osquery/osquery/pull/7676))
- Update the "new release" issue template ([#7607](https://github.com/osquery/osquery/pull/7607))
- clarify browser_plugins table is referencing basically unsupported CNPAPI tech ([#7651](https://github.com/osquery/osquery/pull/7651))

### Build

- Add an option to build with the leak sanitizer ([#7609](https://github.com/osquery/osquery/pull/7609))
- Fix check for PIE support ([#7234](https://github.com/osquery/osquery/pull/7234))
- Fix SchedulerTests.test_scheduler_drift_accumulation flakyness ([#7613](https://github.com/osquery/osquery/pull/7613))
- Improve config parsing and osqueryfuzz-config performance ([#7635](https://github.com/osquery/osquery/pull/7635))
- Initialize users and groups services on all tests that need them ([#7620](https://github.com/osquery/osquery/pull/7620))
- ci: Update osquery-packaging commit to the latest one ([#7667](https://github.com/osquery/osquery/pull/7667))
- cmake: Add an option to enable or disable using ccache ([#7671](https://github.com/osquery/osquery/pull/7671))
- libs: Update OpenSSL to version 1.1.1o ([#7629](https://github.com/osquery/osquery/pull/7629))
- libs: Update OpenSSL to version 1.1.1q ([#7674](https://github.com/osquery/osquery/pull/7674))
- libs: Update libarchive to version 3.6.1 ([#7654](https://github.com/osquery/osquery/pull/7654))
- libs: Update sqlite to version 3.38.5 ([#7628](https://github.com/osquery/osquery/pull/7628))

<a name="5.3.0"></a>
## [5.3.0](https://github.com/osquery/osquery/releases/tag/5.3.0)

[Git Commits](https://github.com/osquery/osquery/compare/5.2.3...5.3.0)

osquery 5.3.0 brings several table improvements and bugfixes.
Worth mentioning also the deprecation of the `smart_drive_info` table
and the new warning added when incorrectly configuring a CLI only flag
via the config file. In the next release CLI only flags will not be
configurable through the config file or refresh anymore.

This release represents commits from 15 contributors! Thank you all.

### Deprecation Notices

- Deprecate unmaintainable legacy table, `smart_drive_info` ([#7464](https://github.com/osquery/osquery/issues/7464), [#7542](https://github.com/osquery/osquery/pull/7542))

### New Features

- Add the option `tls_disable_status_log` to prevent status logs from being sent via TLS [#7550](https://github.com/osquery/osquery/pull/7550)
- Add SQLite function `in_cidr_block` to check if IPv4/v6 addresses are within the supplied CIDR block [#7563](https://github.com/osquery/osquery/pull/7563)

### Table Changes

- Add the `admindir` column to the `deb_packages` table to parse package databases on different paths [#7549](https://github.com/osquery/osquery/pull/7549)
- Implement and fix `wifi_networks` on macOS Big Sur and newer [#7503](https://github.com/osquery/osquery/pull/7503)
- Add windows/darwin support to `npm_packages` [#7536](https://github.com/osquery/osquery/pull/7536)
- Move `apt_sources` and `yum_sources` tables to linux only [#7537](https://github.com/osquery/osquery/pull/7537)
- Add homebrew paths to the `python_packages` table [#7535](https://github.com/osquery/osquery/pull/7535)
- Mark `wall_time` column in `osquery_schedule` as hidden [#7501](https://github.com/osquery/osquery/pull/7501)
- Add new metrics and improve description of existing ones in `osquery_schedule` [#7438](https://github.com/osquery/osquery/pull/7438)
- Add the `mirrorlist` column in the table `yum_sources` [#7479](https://github.com/osquery/osquery/pull/7479)
- Implement `output_size` for `osquery_schedule` [#7436](https://github.com/osquery/osquery/pull/7436)
- `deb_packages` table: Use additional instead of index for the `admindir` column [#7573](https://github.com/osquery/osquery/pull/7573)
- `certificates` table: Add Linux support [#7570](https://github.com/osquery/osquery/pull/7570)
- Add `translated` column to `processes` table to indicate whether the process is running under Apple Rosetta [#7507](https://github.com/osquery/osquery/pull/7507)
- Add the "internet password" type to the macOS `keychain_items` table [#7576](https://github.com/osquery/osquery/pull/7576)
- Add `original filename` column to `file` table on Windows [#7156](https://github.com/osquery/osquery/pull/7156)

### Bug Fixes

- Fix watchdog not killing unhealthy worker/extension fast enough [#7474](https://github.com/osquery/osquery/pull/7474)
- Fix the `test_http_server.py` `--persist` option [#7497](https://github.com/osquery/osquery/pull/7497)
- Update`profile.py --leaks` for python3 [#7534](https://github.com/osquery/osquery/pull/7534)
- Fixes osquery tls connections to aws kinesis when tls_server_certs is set [#7450](https://github.com/osquery/osquery/pull/7450)
- Fix parsing issue when a backslash as the last character on sudoers file line [#7440](https://github.com/osquery/osquery/pull/7440)
- Change the JSON of the results coming from an event scheduled query to an array [#7434](https://github.com/osquery/osquery/pull/7434)
- Fix globToRegex truncating UTF16 characters [#7430](https://github.com/osquery/osquery/pull/7430)
- Prevent hanging when the WMI server does not respond [#7429](https://github.com/osquery/osquery/pull/7429)
- Fix `python_packages` table so that it lists python packages from any user Python installations [#7414](https://github.com/osquery/osquery/pull/7414)
- Set string size limit on thrift protocol factory to prevent a crash [#7484](https://github.com/osquery/osquery/pull/7484)
- Fix driver image path in `drivers` table [#7444](https://github.com/osquery/osquery/pull/7444)
- Do not remove nonblocking flag when reading "special" files, to prevent hangs [#7530](https://github.com/osquery/osquery/pull/7530)
- Fix crash due to interaction between distributed and config plugin [#7504](https://github.com/osquery/osquery/pull/7504)
- bpf: Disable the BPF publisher in case of error [#7500](https://github.com/osquery/osquery/pull/7500)
- Warn about setting CLI_FLAGs in the config [#7583](https://github.com/osquery/osquery/pull/7583)
- Explicitly set context for the tables reading utmpx databases [#7578](https://github.com/osquery/osquery/pull/7578)
- bpf: Improve socket event handling [#7446](https://github.com/osquery/osquery/pull/7446)
- certificates: Refactor the OpenSSL utilities [#7581](https://github.com/osquery/osquery/pull/7581)
- Fix shared_resources accessing uninitialized variables [#7600](https://github.com/osquery/osquery/pull/7600)

### Under the Hood improvements

- Implement a performant cache for users and groups on Windows [#7516](https://github.com/osquery/osquery/pull/7516)
- Replace WmiRequest constructor with static factory method to improve error handling and prevent crashes [#7489](https://github.com/osquery/osquery/pull/7489)
- Remove redundant string conversion [#7603](https://github.com/osquery/osquery/pull/7603)

### Build

- Fix DebPackages.test_sanity test when the `size` column is empty [#7569](https://github.com/osquery/osquery/pull/7569)
- libs: Update libdpkg from version v1.19.0.5 to v1.21.7 [#7549](https://github.com/osquery/osquery/pull/7549)
- CI: Restore some release checks [#7558](https://github.com/osquery/osquery/pull/7558)
- Prevent ebpfpub linking against the system zlib [#7557](https://github.com/osquery/osquery/pull/7557)
- Fix mdfind.test_sanity flaky behavior [#7533](https://github.com/osquery/osquery/pull/7533)
- Enable fuzzing and Asan on Windows, enable Asan on macOS [#7470](https://github.com/osquery/osquery/pull/7470)
- Update cppcheck to version 2.6.3 and skip analysis for third party code [#7455](https://github.com/osquery/osquery/pull/7455)
- Change `cpu_info` test to expect *at least* one socket, not just one [#7490](https://github.com/osquery/osquery/pull/7490)
- Fix third party libraries flags leaking to osquery targets [#7480](https://github.com/osquery/osquery/pull/7480)
- Add third party libraries target [#7467](https://github.com/osquery/osquery/pull/7467)
- Do not run clang-tidy on third party libraries [#7432](https://github.com/osquery/osquery/pull/7432)
- CI: Create github workflow target to gate mergeability [#7427](https://github.com/osquery/osquery/pull/7427)
- Fix some warnings about unrecognized special characters in the Windows event log test [#7478](https://github.com/osquery/osquery/pull/7478)
- Change where the macOS Info.plist is generated [#7566](https://github.com/osquery/osquery/pull/7566)
- Add OSQUERY_ENABLE_THREAD_SANITIZER to optionally enable TSan [#6997](https://github.com/osquery/osquery/pull/6997)
- Add an option to specify a path to the openssl archive [#7559](https://github.com/osquery/osquery/pull/7559)
- packs: Update reverse shell query pack to check for a valid remote_port [#7567](https://github.com/osquery/osquery/pull/7567)
- Remove the test_daemon_sighup test [#7584](https://github.com/osquery/osquery/pull/7584)
- Fix release tests for Linux aarch64 [#7572](https://github.com/osquery/osquery/pull/7572)


### Documentation

- docs: remove FreeBSD [#7508](https://github.com/osquery/osquery/pull/7508)
- Pin Jinja2 ReadTheDocs dependency to 3.0.3 [#7533](https://github.com/osquery/osquery/pull/7533)
- CHANGELOG 5.2.3 [#7571](https://github.com/osquery/osquery/pull/7571)
- CHANGELOG 5.2.2 [#7447](https://github.com/osquery/osquery/pull/7447)
- Bump mkdocs from 1.1.2 to 1.2.3 in /docs [#7457](https://github.com/osquery/osquery/pull/7457)
- Replace OS X with macOS in table specs [#7587](https://github.com/osquery/osquery/pull/7587)
- Update `osquery.example.conf` to omit the CLI only flags [#7595](https://github.com/osquery/osquery/pull/7595)
- Update documentation about users and groups service flags ([#7596](https://github.com/osquery/osquery/pull/7596))
- Update the TSC members ([#7543](https://github.com/osquery/osquery/pull/7543))

<a name="5.2.3"></a>
## [5.2.3](https://github.com/osquery/osquery/releases/tag/5.2.3)

[Git Commits](https://github.com/osquery/osquery/compare/5.2.2...5.2.3)

Osquery 5.2.3 is a security update that focuses on updating some third-party libraries
which contained CVEs that could affect osquery.
Additionally some other third-party libraries and tables have been dropped,
since they were not maintained or considered safe anymore.

### Deprecation Notices

- Remove the `shortcut_files` table ([#7547](https://github.com/osquery/osquery/pull/7547))
- Remove the ssdeep library and remove its support in the `hash` table ([#7525](https://github.com/osquery/osquery/pull/7525))
- Remove the libelfin library and elf parsing tables ([#7524](https://github.com/osquery/osquery/pull/7524))

### Hardening

- libs: Update OpenSSL from version 1.1.1l to 1.1.1n ([#7506](https://github.com/osquery/osquery/pull/7506))
- libs: Update zlib from v1.2.11 to v1.2.12 ([#7548](https://github.com/osquery/osquery/pull/7548))
- Update librpm to 4.17.0 ([#7529](https://github.com/osquery/osquery/pull/7529))
- libs: Update expat from version 2.2.10 to 2.4.7 ([#7526](https://github.com/osquery/osquery/pull/7526))

<a name="5.2.2"></a>
## [5.2.2](https://github.com/osquery/osquery/releases/tag/5.2.2)

[Git Commits](https://github.com/osquery/osquery/compare/5.1.0...5.2.2)

Osquery 5.2.2 brings native Apple Silicon (M1) support to the macOS
platform. It also represents a comprehensive review and update of our
third-party dependencies. To support this work, the developer docs
have been updated, as have several parts of the build system

This release represents commits from 24 contributors! Thank you all.

### New Features

- Apple Silicon support ([#7330](https://github.com/osquery/osquery/pull/7330))

### Deprecation Notices

- The `cpuid` table is x86 only. See [#7462](https://github.com/osquery/osquery/issues/7462)
- The `smart_drive_info` table has been deprecated, and is not included in the m1 builds. See [#7464](https://github.com/osquery/osquery/issues/7464)
- The `lldp_neighbors` table has been deprecated, and is not included in the m1 builds. See [#7463](https://github.com/osquery/osquery/issues/7463)

### Table Changes

- Update `time` table to always reflect UTC values ([#7276](https://github.com/osquery/osquery/pull/7276), [#7460](https://github.com/osquery/osquery/pull/7460), [#7437](https://github.com/osquery/osquery/pull/7437))
- Hide the deprecated `antispyware` column in `windows_security_center` ([#7411](https://github.com/osquery/osquery/pull/7411))
- Add `windows_firewall_rules` table for windows ([#7403](https://github.com/osquery/osquery/pull/7403))

### Bug Fixes

- Update the ATC table `path` column check to be case insensitive ([#7442](https://github.com/osquery/osquery/pull/7442))
- Fix a crash introduced by 5.2.0 when Yara uses its own strutils functions ([#7439](https://github.com/osquery/osquery/pull/7439))
- Fix `user_time` and `system_time` unit in processes table on M1 ([#7473](https://github.com/osquery/osquery/pull/7473))

### Documentation

- Fix typos in documentation ([#7443](https://github.com/osquery/osquery/pull/7443), [#7412](https://github.com/osquery/osquery/pull/7412))
- CHANGELOG 5.1.0 ([#7406](https://github.com/osquery/osquery/pull/7406))

### Build

- Update sqlite to version 3.37.0 ([#7426](https://github.com/osquery/osquery/pull/7426))
- Fix linking of thirdparty_sleuthkit ([#7425](https://github.com/osquery/osquery/pull/7425))
- Fix how we disable tables in the fuzzer init method ([#7419](https://github.com/osquery/osquery/pull/7419))
- Prevent running discovery queries when fuzzing ([#7418](https://github.com/osquery/osquery/pull/7418))
- Add BOOST_USE_ASAN define when enabling Asan ([#7469](https://github.com/osquery/osquery/pull/7469))
- Removing unnecessary macOS version check ([#7451](https://github.com/osquery/osquery/pull/7451))
- Fix submodule cache for macOS CI runner ([#7456](https://github.com/osquery/osquery/pull/7456))
- Add osquery version to macOS app bundle Info.plist ([#7452](https://github.com/osquery/osquery/pull/7452))
- libs: Update OpenSSL to verion 1.1.1l ([#7330](https://github.com/osquery/osquery/pull/7330))
- libs: Update augeas to version 1.12.0 ([#7330](https://github.com/osquery/osquery/pull/7330))
- libs: Update aws-sdk to version 1.9.116 ([#7330](https://github.com/osquery/osquery/pull/7330))
- libs: Update boost to version 1.77 ([#7330](https://github.com/osquery/osquery/pull/7330))
- libs: Update gflags to 2.2.2 ([#7330](https://github.com/osquery/osquery/pull/7330))
- libs: Update glog to version 0.5.0 ([#7330](https://github.com/osquery/osquery/pull/7330))
- libs: Update googletest to version 1.11.0 ([#7330](https://github.com/osquery/osquery/pull/7330))
- libs: Update libarchive to version 3.5.2 ([#7330](https://github.com/osquery/osquery/pull/7330))
- libs: Update libcap to version 1.2.59 ([#7330](https://github.com/osquery/osquery/pull/7330))
- libs: Update libmagic to version 5.40 ([#7330](https://github.com/osquery/osquery/pull/7330))
- libs: Update librdkafka to version 1.8.0 ([#7330](https://github.com/osquery/osquery/pull/7330))
- libs: Update libxml2 to version 2.9.12 ([#7330](https://github.com/osquery/osquery/pull/7330))
- libs: Update linenoise-ng to the latest commit ([#7330](https://github.com/osquery/osquery/pull/7330))
- libs: Update lzma to version 5.2.5 ([#7330](https://github.com/osquery/osquery/pull/7330))
- libs: Update rocksdb to version 6.22.1 ([#7330](https://github.com/osquery/osquery/pull/7330))
- libs: Update sleuthkit to version 4.11.0 ([#7330](https://github.com/osquery/osquery/pull/7330))
- libs: Update ssdeep-cpp to the latest commit (d8705da) ([#7330](https://github.com/osquery/osquery/pull/7330))
- libs: Update thrift to version 0.15.0 ([#7330](https://github.com/osquery/osquery/pull/7330))
- libs: Update yara to version 4.1.3 ([#7330](https://github.com/osquery/osquery/pull/7330))
- libs: Update zstd to version 1.4.0 ([#7330](https://github.com/osquery/osquery/pull/7330))

<a name="5.1.0"></a>
## [5.1.0](https://github.com/osquery/osquery/releases/tag/5.1.0)

[Git Commits](https://github.com/osquery/osquery/compare/5.0.1...5.1.0)

Representing commits from 20 contributors! Thank you all.

### New Features

- Allow custom cpu limit duration for the watchdog ([#7348](https://github.com/osquery/osquery/pull/7348))
- Support custom endpoints for AWS Kinesis and Firehose. ([#7317](https://github.com/osquery/osquery/pull/7317))

### Table Changes

- Add `docker_container_envs` table for access to docker container environment ([#7313](https://github.com/osquery/osquery/pull/7313))
- `curl` table now returns peer certificates even if the TLS handshake does not complete ([#7349](https://github.com/osquery/osquery/pull/7349))

### Under the Hood improvements

- Allow tests and SDK to reset dispatcher state ([#7372](https://github.com/osquery/osquery/pull/7372))
- Avoid string copies when looping through cron search dirs ([#7331](https://github.com/osquery/osquery/pull/7331))
- Respect `read_max` flag when hashing using ssdeep ([#7367](https://github.com/osquery/osquery/pull/7367))

### Bug Fixes

- Detect when an extension has not started correctly on Windows ([#7355](https://github.com/osquery/osquery/pull/7355))
- Fix crash #7353 when osquery captures kill syscall when not subscribed to them ([#7354](https://github.com/osquery/osquery/pull/7354))
- Fix crash in AuditdNetlinkReader::configureAuditService when audit_add_rule_data returns an error ([#7337](https://github.com/osquery/osquery/pull/7337))
- Fix crash when `windows_security_products` errors out ([#7401](https://github.com/osquery/osquery/pull/7401))
- Fix for #7394 where cleanup of some event tables never occurs ([#7395](https://github.com/osquery/osquery/pull/7395))
- Improve BPF publisher reliability ([#7302](https://github.com/osquery/osquery/pull/7302))
- Lower log level of "executing distributed query" ([#7386](https://github.com/osquery/osquery/pull/7386))
- Reduce excessive log messages from `authorized_keys` table implementation ([#7318](https://github.com/osquery/osquery/pull/7318))

### Documentation

- Add 5.0.1 CHANGELOG ([#7284](https://github.com/osquery/osquery/pull/7284))
- Fix typo in Everything in SQL docs ([#7338](https://github.com/osquery/osquery/pull/7338))
- Fix typo in SQL docs ([#7376](https://github.com/osquery/osquery/pull/7376))
- Update GitHub issue templates ([#7361](https://github.com/osquery/osquery/pull/7361), [#7396](https://github.com/osquery/osquery/pull/7396))
- Update installation guide to use newer macOS paths ([#7311](https://github.com/osquery/osquery/pull/7311))
- Update macOS ESF documentation ([#7303](https://github.com/osquery/osquery/pull/7303))

### Packs

- Add Forcepoint Endpoint Chrome Extension detection to packs ([#7346](https://github.com/osquery/osquery/pull/7346))
- Add `beurk` rootkit detection to packs ([#7345](https://github.com/osquery/osquery/pull/7345))

### Build

- Allow tests to reset the restarting state ([#7373](https://github.com/osquery/osquery/pull/7373))
- Build librpm with ndb support ([#7294](https://github.com/osquery/osquery/pull/7294))
- Customizable installation logic ([#7315](https://github.com/osquery/osquery/pull/7315))
- Fix ASL test on macOS 11 and later ([#7320](https://github.com/osquery/osquery/pull/7320))
- Restore query packs in Windows packaging ([#7388](https://github.com/osquery/osquery/pull/7388))
- Skip deprecated ASL test when targeting macOS 10.13+ SDK ([#7358](https://github.com/osquery/osquery/pull/7358))
- Update packaging commit to fix Linux symlinks ([#7404](https://github.com/osquery/osquery/pull/7404))
- Update the CI Linux Docker image ([#7332](https://github.com/osquery/osquery/pull/7332))

<a name="5.0.1"></a>
## [5.0.1](https://github.com/osquery/osquery/releases/tag/5.0.1)

[Git Commits](https://github.com/osquery/osquery/compare/4.9.0...5.0.1)

Representing commits from 21 contributors! Thank you all.

osquery 5.0 is a tremendously exciting release!
* We now install into /opt/osquery on macOS and Linux for better portability.
* Our default and recommended installation for macOS uses an application bundle to support entitlement-based features.
* We now use Endpoint Security APIs for various event-based tables on macOS (more to come in the future!)
* We now use an osquery-organization macOS code signing certificate.

There are several breaking changes:
* Installation paths have changes from `/usr/local` to `/opt/osquery` on macOS and Linux (symlinks to executables are provided).
* macOS codesigning is now down through the Osquery Foundation account
* If you manage macOS full disk permission through a profile, you will need to update it.
  See [docs](https://osquery.readthedocs.io/en/latest/deployment/process-auditing/#automatically-granting-permissions-silent-installs)
* We removed the deprecated `blacklist` key from the configuration (#7153)
* Search semantics on the augeas table have changed to be more performant, but do break the existing query API.

### Table Changes

- Add `secureboot` table for Linux and Windows ([#7202](https://github.com/osquery/osquery/pull/7202))
- Add `tpm_info` for Windows ([#7107](https://github.com/osquery/osquery/pull/7107))
- Fix `osquery_info` build_platform column value on Linux ([#7254](https://github.com/osquery/osquery/pull/7254))
- Support `pid_with_namespace` in more tables ([#7132](https://github.com/osquery/osquery/pull/7132))
- Update `augeas` table to use native pattern matching (BREAKING) ([#6982](https://github.com/osquery/osquery/pull/6982))
- Update `chrome_extensions` to include Edge & EdgeBeta ([#7170](https://github.com/osquery/osquery/pull/7170))
- Update `disk_encryption` table to support QueryContext ([#7209](https://github.com/osquery/osquery/pull/7209))
- Update `last` to include utmp type name column ([#7201](https://github.com/osquery/osquery/pull/7201))
- Update `sudoers` table to support newer include syntax ([#7185](https://github.com/osquery/osquery/pull/7185))
- Update `user_ssh_keys` to detect encryption of ed25519 keys ([#7168](https://github.com/osquery/osquery/pull/7168))

### Under the Hood Improvements

- Add ruby namespace to the thrift definition ([#7191](https://github.com/osquery/osquery/pull/7191))
- Always initialize variable change in PerformanceChange ([#7176](https://github.com/osquery/osquery/pull/7176))
- Remove deprecated `blacklist` key ([#7153](https://github.com/osquery/osquery/pull/7153))
- Use total_size within watchdog on Windows ([#7157](https://github.com/osquery/osquery/pull/7157))
- Support AF_PACKET sockets reporting on Linux ([#7282](https://github.com/osquery/osquery/pull/7282))
- socket_events improvements in Linux audit system ([#7269](https://github.com/osquery/osquery/pull/7269))

### Bug Fixes

- Add case sensitive pragma to the pragma/actions authorizer allow list ([#7267](https://github.com/osquery/osquery/pull/7267))
- Add feature to skip denylist for event-based queries ([#7158](https://github.com/osquery/osquery/pull/7158))
- Change logger_mode flag to be correctly interpreted as an octal ([#7273](https://github.com/osquery/osquery/pull/7273))
- Do not let osquery create multiple copies of the extension running at once ([#7178](https://github.com/osquery/osquery/pull/7178))
- Fix Linux audit rule removal upon osquery exit ([#7221](https://github.com/osquery/osquery/pull/7221))
- Fix broadcasting empty logs to logger plugins ([#7183](https://github.com/osquery/osquery/pull/7183))
- Fix issues applying ACLs during chocolatey deployment ([#7166](https://github.com/osquery/osquery/pull/7166))
- Fix memory issue in Windows fileops ([#7179](https://github.com/osquery/osquery/pull/7179))
- Fix `process_open_sockets` type error on darwin ([#6546](https://github.com/osquery/osquery/pull/6546))
- Make sure that the file action `MOVED_TO` is tracked with yara events. ([#7203](https://github.com/osquery/osquery/pull/7203))
- Prevent osquery from killing itself when the `--force` flag is used ([#7295](https://github.com/osquery/osquery/pull/7295))
- Prevent race condition between shutdown and worker or extension launch ([#7204](https://github.com/osquery/osquery/pull/7204))

### Documentation

- Add a security assurance case ([#7048](https://github.com/osquery/osquery/pull/7048))
- Bring the YARA wiki page up to date ([#7172](https://github.com/osquery/osquery/pull/7172))
- Spelling fixes ([#7211](https://github.com/osquery/osquery/pull/7211), [#7186](https://github.com/osquery/osquery/pull/7186))
- Update `uptime` table description ([#7270](https://github.com/osquery/osquery/pull/7270))
- Update osquery installed artifacts paths in the documentation ([#7286](https://github.com/osquery/osquery/pull/7286))

### Build

- Add TimeoutStopSec to systemd service files ([#7190](https://github.com/osquery/osquery/pull/7190))
- Correct macOS installed app bundle path in osqueryctl and doc ([#7289](https://github.com/osquery/osquery/pull/7289))
- Create an macOS app bundle ([#7263](https://github.com/osquery/osquery/pull/7263))
- Fix choco packaging not failing when an error occurs during install or upgrade ([#7182](https://github.com/osquery/osquery/pull/7182))
- Fix path in macOS launchd plist ([#7288](https://github.com/osquery/osquery/pull/7288))
- Pin the packaging repo within GitHub workflows ([#7208](https://github.com/osquery/osquery/pull/7208), [#7255](https://github.com/osquery/osquery/pull/7255), [#7279](https://github.com/osquery/osquery/pull/7279))
- Update Windows deployment icon to png ([#7163](https://github.com/osquery/osquery/pull/7163))
- Update install paths, and remove deprecated Facebook naming ([#7210](https://github.com/osquery/osquery/pull/7210))
- Update macOS build to include app bundle related files ([#7184](https://github.com/osquery/osquery/pull/7184))
- Update osquery installed artifacts default paths in code ([#7285](https://github.com/osquery/osquery/pull/7285))
- Update the installation path on Linux ([#7271](https://github.com/osquery/osquery/pull/7271))
- libs: Add options to AWS Optionally enable debug option and restrict content-type header size for PUT req ([#7216](https://github.com/osquery/osquery/pull/7216))
- libs: Enable and compile the YARA macho module on macOS ([#7174](https://github.com/osquery/osquery/pull/7174))
- libs: Update OpenSSL to version 1.1.1l ([#7293](https://github.com/osquery/osquery/pull/7293))
- libs: Update Strawberry Perl to 5.32.1.1, use HTTPS downloads ([#7199](https://github.com/osquery/osquery/pull/7199))
- libs: Update ebpfpub ([#7173](https://github.com/osquery/osquery/pull/7173), [#7219](https://github.com/osquery/osquery/pull/7219))

<a name="4.9.0"></a>
## [4.9.0](https://github.com/osquery/osquery/releases/tag/4.9.0)

[Git Commits](https://github.com/osquery/osquery/compare/4.8.0...4.9.0)

Representing commits from 16 contributors! Thank you all.

### New Features

- Add filesystem logrotate feature ([#7015](https://github.com/osquery/osquery/pull/7015))
- Add Non-Functional EndpointSecurity based process events to macOS (Requires updated codesigning due in 5.0) ([#7046](https://github.com/osquery/osquery/pull/7046))

### Table Changes

- Add `mdm_managed` column to `system_extensions` on macOS ([#6915](https://github.com/osquery/osquery/pull/6915))
- Add `prefetch` table on Windows ([#7076](https://github.com/osquery/osquery/pull/7076))
- Add support for IMDSv2 to AWS tables ([#7084](https://github.com/osquery/osquery/pull/7084))
- Enable container stats on docker containers that don't have traditional networks ([#7145](https://github.com/osquery/osquery/pull/7145))
- Update `homebrew_packages` to include new prefix, and allow specifying alternate prefixes ([#7117](https://github.com/osquery/osquery/pull/7117))
- Update `ntfs_acl_permissions` to list all ACE entries (using  `GetAce()`) ([#7114](https://github.com/osquery/osquery/pull/7114))
- Update `processes` table to display additional Windows attributes (`secured`, `protected`, `virtual`, `elevated`) ([#7121](https://github.com/osquery/osquery/pull/7121))
- Update how `package_install_history` identifies the packageIdentifiers key ([#7099](https://github.com/osquery/osquery/pull/7099))
- Update how `identifier` is calculated in `chrome_extensions` ([#7124](https://github.com/osquery/osquery/pull/7124))

### Under the Hood improvements

- Improve speed of osquery shutdown procedure ([#7077](https://github.com/osquery/osquery/pull/7077))
- Improve shutdown speed during initialization ([#7106](https://github.com/osquery/osquery/pull/7106))
- Update website generators ([#7136](https://github.com/osquery/osquery/pull/7136))
- CLI flag to allow osquery to keep retrying enrollment (instead of exiting) ([#7125](https://github.com/osquery/osquery/pull/7125))
- rocksdb: Do not fsync WAL writes ([#7094](https://github.com/osquery/osquery/pull/7094))
- Move CPack packaging to a dedicated repository ([#7059](https://github.com/osquery/osquery/pull/7059))
- Restore thrift socket 5min timeout ([#7072](https://github.com/osquery/osquery/pull/7072))
- Consolidate syscalls to a single audit rule ([#7063](https://github.com/osquery/osquery/pull/7063))

### Bug Fixes

- Add current WMI location for Dell BIOS info ([#7103](https://github.com/osquery/osquery/pull/7103))
- Correct RocksDB error code and subcode printing on open failure ([#7069](https://github.com/osquery/osquery/pull/7069))
- Fix `pipe_channel` not reading all data in a message ([#7139](https://github.com/osquery/osquery/pull/7139))
- Fix crash and deadlocks in recursive logging ([#7127](https://github.com/osquery/osquery/pull/7127))
- Fix custom `curl_certificate` timeouts ([#7151](https://github.com/osquery/osquery/pull/7151))
- Fix extensions crash on shutdown ([#7075](https://github.com/osquery/osquery/pull/7075))
- Handle updated paths on various macOS tables -- `xprotect_entries`, `xprotect_meta`, `launchd` ([#7138](https://github.com/osquery/osquery/pull/7138), [#7154](https://github.com/osquery/osquery/pull/7154))
- Trigger event cleanup checks every 256 events ([#7143](https://github.com/osquery/osquery/pull/7143))
- Update generating an extension uuid to be thread safe ([#7135](https://github.com/osquery/osquery/pull/7135))
- Watchdog should wait for the worker to shutdown ([#7116](https://github.com/osquery/osquery/pull/7116))

### Documentation

- Update process auditing requirements documentation ([#7102](https://github.com/osquery/osquery/pull/7102))
- Update website docs indicating windows support for YARA tables ([#7130](https://github.com/osquery/osquery/pull/7130))
- Add 4.9.0 CHANGELOG ([#7152](https://github.com/osquery/osquery/pull/7152))

### Build

- Add Apple provisioning profile for distribution ([#7119](https://github.com/osquery/osquery/pull/7119))
- Add more tests for events expiration ([#7071](https://github.com/osquery/osquery/pull/7071))
- CI: Regenerate sccache cache when compiler version changes ([#7081](https://github.com/osquery/osquery/pull/7081))
- Fix flaky test test_daemon_sigint by waiting for pidfile ([#7095](https://github.com/osquery/osquery/pull/7095))
- Fix icon in Windows packaging ([#7148](https://github.com/osquery/osquery/pull/7148))
- Minor cleanup of unused variables ([#7128](https://github.com/osquery/osquery/pull/7128))
- Print extension SDK minimum version required when failing to load ([#7074](https://github.com/osquery/osquery/pull/7074))
- Remove POSIX-only `-fexceptions` flag on Windows ([#7126](https://github.com/osquery/osquery/pull/7126))
- Remove duplicated osquery_utils_aws_tests-test ([#7078](https://github.com/osquery/osquery/pull/7078))
- Remove flaky test decorators for python tests ([#7070](https://github.com/osquery/osquery/pull/7070))
- Update SQLite to version 3.35.5 ([#7090](https://github.com/osquery/osquery/pull/7090))
- Update librdkafka to version 1.7.0 ([#7134](https://github.com/osquery/osquery/pull/7134))
- Update libyara to version 4.1.1 ([#7133](https://github.com/osquery/osquery/pull/7133))

<a name="4.8.0"></a>
## [4.8.0](https://github.com/osquery/osquery/releases/tag/4.8.0)

[Git Commits](https://github.com/osquery/osquery/compare/4.7.0...4.8.0)

Representing commits from 14 contributors! Thank you all.

This version fixes a regression introduced in 4.7.0 related to events
expiration optimization.  Please read
([#7055](https://github.com/osquery/osquery/pull/7055)) for more
information.

This release upgrades openssl, as is general good practice. Osquery is
not known to be effected by any security issues in OpenSSL.

### New Features

- shell: Add `.connect` meta command ([#6944](https://github.com/osquery/osquery/pull/6944))

### Table Changes

- Add `seccomp_events` table for Linux ([#7006](https://github.com/osquery/osquery/pull/7006))
- Add `shortcut_files` table for Windows ([#6994](https://github.com/osquery/osquery/pull/6994))

### Under the Hood improvements

- Removing Keyboard Event Taps from osx-attacks pack ([#7023](https://github.com/osquery/osquery/pull/7023))
- Refactor watcher out of singleton pattern ([#7042](https://github.com/osquery/osquery/pull/7042))
- Small events subscriber refactor to increase test coverage ([#7050](https://github.com/osquery/osquery/pull/7050))
- Setting non-required `deb_packages` fields as optional in test ([#7001](https://github.com/osquery/osquery/pull/7001))

### Bug Fixes

- Handle events optimization edge cases ([#7060](https://github.com/osquery/osquery/pull/7060))
- Fix optimization for multiple queries using the same subscriber ([#7055](https://github.com/osquery/osquery/pull/7055))
- Use epoch and counter for events-based queries ([#7051](https://github.com/osquery/osquery/pull/7051))
- Guard node key to prevent duplicate enrollments ([#7052](https://github.com/osquery/osquery/pull/7052))
- Change windows calculation for physical_memory ([#7028](https://github.com/osquery/osquery/pull/7028))
- Free using WTSFreeMemoryEx for WTSEnumerateSessionsExW ([#7039](https://github.com/osquery/osquery/pull/7039))
- Release variable in Windows data conversation ([#7024](https://github.com/osquery/osquery/pull/7024))
- Change `chrome_extensions` warnings to verbose ([#7032](https://github.com/osquery/osquery/pull/7032))
- Add transactions to the SQLite authorizer PRAGMAs ([#7029](https://github.com/osquery/osquery/pull/7029))
- Change Windows messages to verbose ([#7027](https://github.com/osquery/osquery/pull/7027))
- Fix scheduler to print the correct number of elapsed seconds ([#7016](https://github.com/osquery/osquery/pull/7016))

### Documentation

- Fix `tls_enroll_max_attempts` flag name in the documentation ([#7049](https://github.com/osquery/osquery/pull/7049))
- Improve docs on FIM, mention NTFS and Audit, etc. ([#7036](https://github.com/osquery/osquery/pull/7036))
- config: Add docs for the events top-level-key ([#7040](https://github.com/osquery/osquery/pull/7040))
- Add funding link on GitHub generated page ([#7043](https://github.com/osquery/osquery/pull/7043))
- Correct the example in the `windows_events` table spec ([#7035](https://github.com/osquery/osquery/pull/7035))
- Correct docs about OpenSSL and TLS behavior ([#7033](https://github.com/osquery/osquery/pull/7033))
- Update docs to describe how to build for aarch64/arm64 (#6285) ([#6970](https://github.com/osquery/osquery/pull/6970))
- Add a note on enabling Windows to build with CMake's long paths ([#7010](https://github.com/osquery/osquery/pull/7010))
- Add 4.8.0 CHANGELOG ([#7057](https://github.com/osquery/osquery/pull/7057))

### Build

- Add an option to enable incremental linking on Windows ([#7044](https://github.com/osquery/osquery/pull/7044))
- Remove Buck leftovers that supported building with old versions of OpenSSL ([#7034](https://github.com/osquery/osquery/pull/7034))
- Add build_aarch64 workflow for push ([#7014](https://github.com/osquery/osquery/pull/7014))
- Move CI to using docker from osquery ([#7012](https://github.com/osquery/osquery/pull/7012))
- Update dockerfile to multiplatform ([#7011](https://github.com/osquery/osquery/pull/7011))
- Run GH Actions workflows on all tags ([#7004](https://github.com/osquery/osquery/pull/7004))
- Disable BPF events tests if OSQUERY_BUILD_BPF is false ([#7002](https://github.com/osquery/osquery/pull/7002))
- libs: Update OpenSSL to version 1.1.1k ([#7026](https://github.com/osquery/osquery/pull/7026))

<a name="4.7.0"></a>
## [4.7.0](https://github.com/osquery/osquery/releases/tag/4.7.0)

[Git Commits](https://github.com/osquery/osquery/compare/4.6.0...4.7.0)

Commits from 21 contributors! Thank you all!

### New Features

- Add `concat` and `concat_ws` sql functions ([#6927](https://github.com/osquery/osquery/pull/6927))
- Update the scheduler to log the query name at info level ([#6934](https://github.com/osquery/osquery/pull/6934))
- Add support for SQLite RPM databases ([#6939](https://github.com/osquery/osquery/pull/6939))

### Table Changes

- Add `computer` column to Windows Eventlogs ([#6952](https://github.com/osquery/osquery/pull/6952))
- Add `docker_image_history` table ([#6884](https://github.com/osquery/osquery/pull/6884))
- Add `filevault_status` column to disk_encryption table ([#6823](https://github.com/osquery/osquery/pull/6823))
- Add `location_services` table on macOS ([#6826](https://github.com/osquery/osquery/pull/6826))
- Add `shellbags` table ([#6949](https://github.com/osquery/osquery/pull/6949))
- Add `system_extensions` table on macOS ([#6863](https://github.com/osquery/osquery/pull/6863))
- Add `systemd_units` table ([#6593](https://github.com/osquery/osquery/pull/6593))
- Add `ycloud_instance_metadata` table ([#6961](https://github.com/osquery/osquery/pull/6961))
- Fix loading of YARA rules on Windows ([#6893](https://github.com/osquery/osquery/pull/6893))
- Fix macOS OpenDirectory attribute mismatch ([#6816](https://github.com/osquery/osquery/pull/6816))
- Update `augeas` table not to  autoload system lenses ([#6980](https://github.com/osquery/osquery/pull/6980))
- Update `chrome_extensions` table -- more browser support and tests ([#6780](https://github.com/osquery/osquery/pull/6780))
- Update `office_mru` table to correct platforms ([#6827](https://github.com/osquery/osquery/pull/6827))
- Update aws table to include macOS ([#6817](https://github.com/osquery/osquery/pull/6817))

### Under the Hood improvements

- Remove Azure Pipelines ([#6953](https://github.com/osquery/osquery/pull/6953))
- Disable deprecated TLS versions 1.0, 1.1 ([#6910](https://github.com/osquery/osquery/pull/6910))
- Use librpm bdb_ro backend and remove bdb ([#6931](https://github.com/osquery/osquery/pull/6931))
- bpf: Improve execve/execveat tracing, add AArch64 build support ([#6802](https://github.com/osquery/osquery/pull/6802))
- Use a distinct carver `request_id` and add this to the schema ([#6959](https://github.com/osquery/osquery/pull/6959))
- Initialize TLSLogForwarder before enrollment check ([#6958](https://github.com/osquery/osquery/pull/6958))
- Put noisy thrift logs behind a flag ([#6951](https://github.com/osquery/osquery/pull/6951))
- Fix bug in windows thrift, causing named pipe closing ([#6937](https://github.com/osquery/osquery/pull/6937))
- Remove unused/experimental ebpf code ([#6879](https://github.com/osquery/osquery/pull/6879))
- Remove unused ev2 code ([#6878](https://github.com/osquery/osquery/pull/6878))
- Refactor the eventing framework to reduce disk IO and improve performance([#6610](https://github.com/osquery/osquery/pull/6610))

### Bug Fixes

- Add `journal_mode` to the sqlite authorizer PRAGMAs ([#6999](https://github.com/osquery/osquery/pull/6999))
- Add `table_info` to the sqlite authorizer PRAGMAs ([#6814](https://github.com/osquery/osquery/pull/6814))
- Always use BIGINT macro for `long long` data ([#6986](https://github.com/osquery/osquery/pull/6986))
- Copy JSON objects to avoid MemoryPool buildup ([#6957](https://github.com/osquery/osquery/pull/6957))
- Do not call unconfigured subscribers errors ([#6847](https://github.com/osquery/osquery/pull/6847))
- Do not ignore mountpoints that have the same mount path ([#6871](https://github.com/osquery/osquery/pull/6871))
- Do not start scheduler when shutting down ([#6960](https://github.com/osquery/osquery/pull/6960))
- Don't mark scope and key columns as index in selinux_settings table ([#6872](https://github.com/osquery/osquery/pull/6872))
- Fix `augeas` table output bug for non-path entries ([#6981](https://github.com/osquery/osquery/pull/6981))
- Fix `pids` column in `docker_container_stats` table ([#6965](https://github.com/osquery/osquery/pull/6965))
- Fix additional relative path check in Yara for Windows ([#6894](https://github.com/osquery/osquery/pull/6894))
- Fix config validation oom with duplicated keys ([#6876](https://github.com/osquery/osquery/pull/6876))
- Fix data type macro used for 64-bit timestamp variables ([#6897](https://github.com/osquery/osquery/pull/6897))
- Fix error in `process_open_files` inode need stoul, not stoi ([#6983](https://github.com/osquery/osquery/pull/6983))
- Fix leaks when a query fails from the shell ([#6849](https://github.com/osquery/osquery/pull/6849))
- Fix mem leak regression with Windows sids API ([#6984](https://github.com/osquery/osquery/pull/6984))
- Make Group ID columns consistent across Windows tables ([#6987](https://github.com/osquery/osquery/pull/6987))
- When iterating /proc, use individual try/catch so catch partial failures ([#6933](https://github.com/osquery/osquery/pull/6933))
- augeas: Clear aug pointer on error ([#6973](https://github.com/osquery/osquery/pull/6973))

### Documentation

- Add 4.6.0 CHANGELOG ([#6809](https://github.com/osquery/osquery/pull/6809))
- Add 4.7.0 CHANGELOG ([#6985](https://github.com/osquery/osquery/pull/6985))
- Add docs for TLS enroll max attempts ([#6888](https://github.com/osquery/osquery/pull/6888))
- Change reference about Azure Pipelines to GitHub Actions ([#6988](https://github.com/osquery/osquery/pull/6988))
- Clarify FIM exclude category documentation ([#6966](https://github.com/osquery/osquery/pull/6966))
- Document retrieval of available tables/columns via SQL ([#6812](https://github.com/osquery/osquery/pull/6812))
- Fix Github Actions status badge in the README ([#6908](https://github.com/osquery/osquery/pull/6908))
- Fix all broken or redirected URLs and references ([#6835](https://github.com/osquery/osquery/pull/6835))
- Fix broken URL in docs ([#6882](https://github.com/osquery/osquery/pull/6882))
- Fix incorrect Slack URLs ([#6844](https://github.com/osquery/osquery/pull/6844))
- Fix packs discovery queries documentation ([#6946](https://github.com/osquery/osquery/pull/6946))
- Fix reference to a Powershell script on Windows ([#6936](https://github.com/osquery/osquery/pull/6936))
- Fix typos in source code ([#6901](https://github.com/osquery/osquery/pull/6901))
- Improve explanations of event control flags ([#6954](https://github.com/osquery/osquery/pull/6954))
- Spellcheck and Markdown edits ([#6899](https://github.com/osquery/osquery/pull/6899))
- Update README to include release process comment ([#6877](https://github.com/osquery/osquery/pull/6877))
- Update documentation about denylist schedule key ([#6922](https://github.com/osquery/osquery/pull/6922))
- Update macOS OpenBSM configuration ([#6916](https://github.com/osquery/osquery/pull/6916))
- Update the Linux install steps and package listing ([#6956](https://github.com/osquery/osquery/pull/6956))
- Update the info about osquery's TLS version support ([#6963](https://github.com/osquery/osquery/pull/6963))

### Build

- CI: Add a RelWithDebInfo Linux job to generate packages ([#6838](https://github.com/osquery/osquery/pull/6838))
- CI: Add support for GitHub Actions ([#6885](https://github.com/osquery/osquery/pull/6885))
- CI: Add unit tests for RPM DB querying ([#6919](https://github.com/osquery/osquery/pull/6919))
- CI: Fix ExtendedAttributesTableTests failing due to an unexpected attribute ([#6942](https://github.com/osquery/osquery/pull/6942))
- CI: Fix StartupItemTest failing due to unexpected values ([#6940](https://github.com/osquery/osquery/pull/6940))
- CI: Fix SystemControlsTest adding sunrpc as an expected subsystem ([#6932](https://github.com/osquery/osquery/pull/6932))
- CI: Fix XattrTests failing due to unexpected attribute name ([#6941](https://github.com/osquery/osquery/pull/6941))
- CI: Fix an incorrect check in StartupItems test ([#6950](https://github.com/osquery/osquery/pull/6950))
- CI: Fix wifi_tests on macOS 10.15 and above ([#6724](https://github.com/osquery/osquery/pull/6724))
- CI: Move cppcheck step after the tests ([#6845](https://github.com/osquery/osquery/pull/6845))
- CI: Permit running formatting earlier in the CI ([#6836](https://github.com/osquery/osquery/pull/6836))
- CI: Remove incorrect 2to3 symlink breaking Python brew upgrade ([#6819](https://github.com/osquery/osquery/pull/6819))
- CI: Remove unused empty test file ([#6918](https://github.com/osquery/osquery/pull/6918))
- CI: Remove unused tests for Rocksdb and Inmemory db plugins ([#6900](https://github.com/osquery/osquery/pull/6900))
- CI: Update XCode to 12.3 and Update min macOS version to 10.12 ([#6896](https://github.com/osquery/osquery/pull/6896), [#6913](https://github.com/osquery/osquery/pull/6913))
- CI: Update macOS agent to 10.15 Catalina ([#6680](https://github.com/osquery/osquery/pull/6680))
- CMake: Add -pthread compile option on posix platforms ([#6909](https://github.com/osquery/osquery/pull/6909))
- CMake: Add Valgrind support ([#6834](https://github.com/osquery/osquery/pull/6834))
- CMake: Add an option to disable building AWS tables and library ([#6831](https://github.com/osquery/osquery/pull/6831))
- CMake: Add an option to disable building libdpkg tables and library ([#6848](https://github.com/osquery/osquery/pull/6848))
- CMake: Detect missing headers during include namespace generation ([#6855](https://github.com/osquery/osquery/pull/6855))
- CMake: Do not attempt to dllimport Thrift symbols ([#6856](https://github.com/osquery/osquery/pull/6856))
- CMake: Do not compile Windows libraries with debug symbols ([#6833](https://github.com/osquery/osquery/pull/6833))
- CMake: Explicitly set the MSVC runtime library ([#6818](https://github.com/osquery/osquery/pull/6818))
- CMake: Fix amalgamated tables generation on change ([#6832](https://github.com/osquery/osquery/pull/6832))
- CMake: Fix platformtablecontaineripc include namespace generation ([#6853](https://github.com/osquery/osquery/pull/6853))
- CMake: Further fix amalgamation file gen on change ([#6854](https://github.com/osquery/osquery/pull/6854))
- CMake: Refactor and rename fuzzers build flag ([#6829](https://github.com/osquery/osquery/pull/6829))
- CMake: Significantly speed up configuration phase ([#6914](https://github.com/osquery/osquery/pull/6914))
- CMake: Use make jobserver for OpenSSL on Linux and macOS ([#6821](https://github.com/osquery/osquery/pull/6821))
- CPack: Remove extraneous lenses directory for augues on macOS ([#6998](https://github.com/osquery/osquery/pull/6998))
- Change libdpkg submodule url to our own GitHub mirror ([#6903](https://github.com/osquery/osquery/pull/6903))
- Disable incremental linking to reduce build size on Windows ([#6898](https://github.com/osquery/osquery/pull/6898))
- GitHub Actions: Fix .deb artifacts, add scheduled builds ([#6920](https://github.com/osquery/osquery/pull/6920))
- Remove `hash` and `yara` table from fuzz harnesses ([#6972](https://github.com/osquery/osquery/pull/6972))
- libraries: Reduce the compilation units from libarchive ([#6886](https://github.com/osquery/osquery/pull/6886))
- libraries: Remove the last usage of sqlite3 from sleuthkit ([#6858](https://github.com/osquery/osquery/pull/6858))
- libraries: Rename yara str functions to avoid symbol collisions ([#6917](https://github.com/osquery/osquery/pull/6917))
- libraries: Update librpm to version 4.16.1.2 ([#6850](https://github.com/osquery/osquery/pull/6850))
- libraries: Update openssl to version 1.1.1i ([#6820](https://github.com/osquery/osquery/pull/6820))
- libraries: Update thrift to version 0.13.0 ([#6822](https://github.com/osquery/osquery/pull/6822))

### Hardening

- Update CODEOWNERS to reflect existing teams ([#6955](https://github.com/osquery/osquery/pull/6955), [#6975](https://github.com/osquery/osquery/pull/6975))
- Restrict access to Thrift server pipe on Windows ([#6875](https://github.com/osquery/osquery/pull/6875))
- Fix a leak in libdpkg when querying the `deb_packages` table ([#6892](https://github.com/osquery/osquery/pull/6892))
- Fix UB and dangerous casting in the pubsub framework ([#6881](https://github.com/osquery/osquery/pull/6881))
- Fix heap-use-after-free in deregisterEventSubscriber ([#6880](https://github.com/osquery/osquery/pull/6880))
- Thift patch to support security configuration ([#6846](https://github.com/osquery/osquery/pull/6846))
- Improve config fuzzer dictionary creation script ([#6860](https://github.com/osquery/osquery/pull/6860))
- Avoid running queries for views when fuzzing ([#6859](https://github.com/osquery/osquery/pull/6859))
- Improve fuzzing speed and stack trace accuracy ([#6851](https://github.com/osquery/osquery/pull/6851))

<a name="4.6.0"></a>
## [4.6.0](https://github.com/osquery/osquery/releases/tag/4.6.0)

[Git Commits](https://github.com/osquery/osquery/compare/4.5.1...4.6.0)

### New Features

- Initial implementations for BPF-based socket and process events tables ([#6571](https://github.com/osquery/osquery/pull/6571))
- Support EC2 tables on Windows ([#6756](https://github.com/osquery/osquery/pull/6756))

### Under the Hood improvements

- BPF: Add container support to fork/vfork/clone ([#6721](https://github.com/osquery/osquery/pull/6721))
- BPF: Additional improvements on the initial implementation ([#6717](https://github.com/osquery/osquery/pull/6717))
- BPF: Fix the tests ([#6783](https://github.com/osquery/osquery/pull/6783))
- BPF: Fix wrong d_type compare in filesystem classes ([#6774](https://github.com/osquery/osquery/pull/6774))
- BPF: Implement additional syscalls to track file descriptor usage ([#6723](https://github.com/osquery/osquery/pull/6723))
- Remove unused LTCG flag ([#6769](https://github.com/osquery/osquery/pull/6769))
- Support TLS client certificate chains ([#6753](https://github.com/osquery/osquery/pull/6753))
- Refactor carver to use the Scheduler ([#6671](https://github.com/osquery/osquery/pull/6671))
- Add configuration flag to disable file_events by default ([#6663](https://github.com/osquery/osquery/pull/6663))
- libs: Build x86_64 configurations on Ubuntu 14.04 ([#6687](https://github.com/osquery/osquery/pull/6687))
- libs: Port the RocksDB Win7 compatibility patch to the MSBuild generator ([#6765](https://github.com/osquery/osquery/pull/6765))
- libs: Update BPF libraries to support LLVM 11 ([#6775](https://github.com/osquery/osquery/pull/6775))
- libs: Update RocksDB to version 6.14.5 ([#6759](https://github.com/osquery/osquery/pull/6759))
- libs: Update bzip2 to version 1.0.8 ([#6786](https://github.com/osquery/osquery/pull/6786))
- libs: Update ebpfpub to latest version ([#6757](https://github.com/osquery/osquery/pull/6757))
- libs: Update sqlite to version 3.34.0 ([#6804](https://github.com/osquery/osquery/pull/6804))
- libs: update aws-sdk to 1.7.230 ([#6749](https://github.com/osquery/osquery/pull/6749))
- Adding support for pretty-printing JSON results in osqueryi ([#6695](https://github.com/osquery/osquery/pull/6695))

### Table Changes

- Add Yandex Browser support for chrome_extensions ([#6735](https://github.com/osquery/osquery/pull/6735))
- Add additional file stat flags to Darwin (bsd_flags) ([#6699](https://github.com/osquery/osquery/pull/6699))
- Add extended_attributes table to Linux, add support for Linux capabilities ([#6195](https://github.com/osquery/osquery/pull/6195))
- Add indexed column support to Windows users table ([#6782](https://github.com/osquery/osquery/pull/6782))
- Enable AWS Instance profile as credential provider on Windows ([#6754](https://github.com/osquery/osquery/pull/6754))
- Add systemd support for startup_items on Linux ([#6562](https://github.com/osquery/osquery/pull/6562))

### Bug Fixes

- Do not use memset on VirtualTable, a non-POD type ([#6760](https://github.com/osquery/osquery/pull/6760))
- Fix deadlock when registering two extensions ([#6745](https://github.com/osquery/osquery/pull/6745))
- Fix last_connected column in wifi_networks on Catalina ([#6669](https://github.com/osquery/osquery/pull/6669))
- Fix missing negations, duplicate rows in iptables table ([#6713](https://github.com/osquery/osquery/pull/6713))
- Fix shadow table to detect empty passwords ([#6696](https://github.com/osquery/osquery/pull/6696))
- Free memory allocated by ConvertStringSidToSid ([#6714](https://github.com/osquery/osquery/pull/6714))
- PackageIdentifiers are optional in InstallHistory.plist ([#6767](https://github.com/osquery/osquery/pull/6767))
- Removing PUNYCODE flag from windows string conversions ([#6730](https://github.com/osquery/osquery/pull/6730))
- Fix memory leak in the dbus classes ([#6773](https://github.com/osquery/osquery/pull/6773))
- Change the kernel_modules size column type to BIGINT ([#6712](https://github.com/osquery/osquery/pull/6712))

### Documentation

- Add a README.md to source-based libraries ([#6686](https://github.com/osquery/osquery/pull/6686))
- Fix spelling typos ([#6705](https://github.com/osquery/osquery/pull/6705))
- Journald Audit Logs Masking Documentation ([#6748](https://github.com/osquery/osquery/pull/6748))

### Build

- CI: Provide built packages as Azure artifacts ([#6772](https://github.com/osquery/osquery/pull/6772))
- CI: Python installation improvements on Windows ([#6764](https://github.com/osquery/osquery/pull/6764))
- CI: Update brew scripts ([#6794](https://github.com/osquery/osquery/pull/6794))
- CMake: Disable BPF support if the LLVM libs are not compatible ([#6746](https://github.com/osquery/osquery/pull/6746))
- CMake: Use CPACK_RPM_PACKAGE_RELEASE ([#6805](https://github.com/osquery/osquery/pull/6805))
- CMake: Add max version limit to 3.18.0 on Linux ([#6801](https://github.com/osquery/osquery/pull/6801))
- Change urls for submodules gpg-error, libgcrypt, libcap ([#6768](https://github.com/osquery/osquery/pull/6768))
- Reduce linkage requirements for tests ([#6715](https://github.com/osquery/osquery/pull/6715))
- Remove a Buck leftover ([#6799](https://github.com/osquery/osquery/pull/6799))
- Remove boost workaround introduced in #5591 for string_view ([#6771](https://github.com/osquery/osquery/pull/6771))
- Tests: Fix tests on Catalina ([#6704](https://github.com/osquery/osquery/pull/6704))
- Update cmake_minum_required to 3.17.5 and pin version in CI ([#6770](https://github.com/osquery/osquery/pull/6770))
- build: Fix Windows build on newer MSVC ([#6732](https://github.com/osquery/osquery/pull/6732))
- extensions: Always compile examples to prevent them from breaking ([#6747](https://github.com/osquery/osquery/pull/6747))

### Security Issues

- Add SQLite authorizer to mitgate CVE-2020-26273 / GHSA-4g56-2482-x7q8 (https://github.com/osquery/osquery/commit/c3f9a3dae22d43ed3b4f6a403cbf89da4cba7c3c)

### Packs

- Updated unwanted-chrome-extensions ([#6720](https://github.com/osquery/osquery/pull/6720))
- Restrict the usb_devices pack to Posix ([#6739](https://github.com/osquery/osquery/pull/6739))
- Add Reptile rootkit to ossec-rootkit pack ([#6703](https://github.com/osquery/osquery/pull/6703))

<a name="4.5.1"></a>
## [4.5.1](https://github.com/osquery/osquery/releases/tag/4.5.1)

[Git Commits](https://github.com/osquery/osquery/compare/4.5.0...4.5.1)

### Under the Hood improvements

- Improve carver tests by faking `postCarve` ([#6659](https://github.com/osquery/osquery/pull/6659))
- Emit an error during carving, if the `carve` SQL function is disabled ([#6658](https://github.com/osquery/osquery/pull/6658))
- Update `carves` specs to allow full scan ([#6657](https://github.com/osquery/osquery/pull/6657))
- Update `carves` table to use JSON ([#6656](https://github.com/osquery/osquery/pull/6656))
- Improve performance and accuracy of Windows `registry` querying ([#6647](https://github.com/osquery/osquery/pull/6647))
- Refactor `ephemeral` database plugin into core and simplify tests ([#6648](https://github.com/osquery/osquery/pull/6648))

### Table Changes

- Support for Office MRU (most recently used) entries ([#6587](https://github.com/osquery/osquery/pull/6587))
- Implement configurable timeout through WHERE clause on `curl_certificate` ([#6641](https://github.com/osquery/osquery/pull/6641))
- Add `atom_packages` table spec to window ([#6649](https://github.com/osquery/osquery/pull/6649))
- Add signature information to `authenticode` table on windows ([#6677](https://github.com/osquery/osquery/pull/6677))
- Add additional AWS regions ([#6666](https://github.com/osquery/osquery/pull/6666))

### Bug Fixes

- Fix container overflow in `curl_certificate` ([#6664](https://github.com/osquery/osquery/pull/6664))
- Fix handling of invalid array bound error with `EvtNext` function ([#6660](https://github.com/osquery/osquery/pull/6660))
- Fix `wmi_bios_info` table searching ([#5246](https://github.com/osquery/osquery/pull/5246))
- Fix `image` column within `drivers` table on Windows ([#6652](https://github.com/osquery/osquery/pull/6652))
- Fix windows `dirPathsAreEqual` to use the documented way ([#6690](https://github.com/osquery/osquery/pull/6690))
- Fix incorrect `stat()` return checking within process_events ([#6694](https://github.com/osquery/osquery/pull/6694))
- Always flush `stdout` when called with `--help` ([#6693](https://github.com/osquery/osquery/pull/6693))

### Documentation

- Document max scheduled query interval ([#6683](https://github.com/osquery/osquery/pull/6683))
- Update documentation around build steps ([#6681](https://github.com/osquery/osquery/pull/6681))
- Documentation copy editing
  ([#6676](https://github.com/osquery/osquery/pull/6676),
  [#6665](https://github.com/osquery/osquery/pull/6665),
  [#6662](https://github.com/osquery/osquery/pull/6662))
- Add 4.5.0 CHANGELOG ([#6646](https://github.com/osquery/osquery/pull/6646))
- Add 4.5.1 CHANGELOG ([#6692](https://github.com/osquery/osquery/pull/6692))

### Build

- Improve flaky python test handling ([#6654](https://github.com/osquery/osquery/pull/6654))
- Restore `test_osqueryi` ([#6631](https://github.com/osquery/osquery/pull/6631))
- Limit `osqueryd` CPU usage to 20% in systemd unit file ([#6644](https://github.com/osquery/osquery/pull/6644))
- Improve flaky `test_osqueryi` ([#6688](https://github.com/osquery/osquery/pull/6688))
- Add `cppcheck` support to macOS ([#6685](https://github.com/osquery/osquery/pull/6685))

### Hardening

- Add exception catching for table execution ([#6689](https://github.com/osquery/osquery/pull/6689))

<a name="4.5.0"></a>
## [4.5.0](https://github.com/osquery/osquery/releases/tag/4.5.0)

[Git Commits](https://github.com/osquery/osquery/compare/4.4.0...4.5.0)

We would like to thank all of the contributors working on
bootstrapping the ARM64/AARCH64 support and Windows 32bit support.
Additionally, we want to thank those working on Unicode support and
all the bug fixes, documentation improvements, and new features.
Thank you! :clap:

### New Features

- ARM64/AARCH64 beta support for Linux ([#6612](https://github.com/osquery/osquery/pull/6612))
- Windows 32bit support ([#6543](https://github.com/osquery/osquery/pull/6543))
- Fix buildup of RocksDB SST files ([#6606](https://github.com/osquery/osquery/pull/6606))

### Under the Hood improvements

- Remove selectAllFrom from Linux `process_events` callback ([#6638](https://github.com/osquery/osquery/pull/6638))
- Remove database read only concept ([#6637](https://github.com/osquery/osquery/pull/6637))
- Move database initialization retry logic into DB API ([#6633](https://github.com/osquery/osquery/pull/6633))
- Move osquery/include files into respective CMake targets ([#6557](https://github.com/osquery/osquery/pull/6557))
- Memoize `EventFactory::getType` ([#6555](https://github.com/osquery/osquery/pull/6555))
- Update schedule counter behavior ([#6223](https://github.com/osquery/osquery/pull/6223))
- Define `UNICODE` and `_UNICODE` preprocessors for windows ([#6338](https://github.com/osquery/osquery/pull/6338))
- Add WMI utility function to convert datetime to FILETIME ([#5901](https://github.com/osquery/osquery/pull/5901))
- Move osquery shutdown logic outside of `Initialize`r ([#6530](https://github.com/osquery/osquery/pull/6530))

### Table Changes

- Support for Windows Background Activity Moderator ([#6585](https://github.com/osquery/osquery/pull/6585))
- Add `apparmor_events` table to Linux ([#4982](https://github.com/osquery/osquery/pull/4982))
- Add `sigurl` column to get YARA signatures from an HTTPS server ([#6607](https://github.com/osquery/osquery/pull/6607))
- Add `sigrules` column to pass YARA signatures within queries ([#6568](https://github.com/osquery/osquery/pull/6568))
- Add non-evented table for querying `windows_event_log` ([#6563](https://github.com/osquery/osquery/pull/6563))
- Improve `chassis_types` and `security_breach` columns within `chassis_info` ([#6608](https://github.com/osquery/osquery/pull/6608))
- Fix bool type usage in `powershell_events` ([#6584](https://github.com/osquery/osquery/pull/6584))
- Add `FileVersionRaw` column to `file` table for Windows ([#5771](https://github.com/osquery/osquery/pull/5771))
- Enable YARA table on Windows ([#6564](https://github.com/osquery/osquery/pull/6564))
- Add `dns_cache` table for Windows ([#6505](https://github.com/osquery/osquery/pull/6505))
- Add support for processing KILL syscall ([#6435](https://github.com/osquery/osquery/pull/6435))
- Add `startup_item`s table for Linux ([#6502](https://github.com/osquery/osquery/pull/6502))
- Add `shimcache` table ([#6463](https://github.com/osquery/osquery/pull/6463))
- Refactor `shell_history` to use generators (it will use less memory) ([#6541](https://github.com/osquery/osquery/pull/6541))

### Bug Fixes

- Set thread names correctly on macOS and Linux ([#6627](https://github.com/osquery/osquery/pull/6627))
- Apply `--scheduler_timeout` correctly ([#6618](https://github.com/osquery/osquery/pull/6618))
- Add check for `character_frequencies` size ([#6625](https://github.com/osquery/osquery/pull/6625))
- Fix race in removing external `TablePlugins` ([#6623](https://github.com/osquery/osquery/pull/6623))
- Force shell to disable watchdog and logger ([#6621](https://github.com/osquery/osquery/pull/6621))
- Return early within the shell if relative flags are used ([#6605](https://github.com/osquery/osquery/pull/6605))
- Apply watcher delay each time the worker is started ([#6604](https://github.com/osquery/osquery/pull/6604))
- Set global output function for Thrift ([#6592](https://github.com/osquery/osquery/pull/6592))
- Fix incorrect `readFile` params in `createPidFile` ([#6578](https://github.com/osquery/osquery/pull/6578))
- Fix call to `LocalFree` on deinit ptr inside `getUidFromSid` ([#6579](https://github.com/osquery/osquery/pull/6579))
- Fix `readFile` to observe requested read size ([#6569](https://github.com/osquery/osquery/pull/6569))
- Replace fstream within `syslog_event`s with a custom non-blocking getline ([#6539](https://github.com/osquery/osquery/pull/6539))
- Only fire events if a publisher exists ([#6553](https://github.com/osquery/osquery/pull/6553))
- Fix Leak in `psidToString` ([#6548](https://github.com/osquery/osquery/pull/6548))
- Fix memory leaks in `rpm_package_files` ([#6544](https://github.com/osquery/osquery/pull/6544))
- Change "Symlink loop" message from warning to verbose ([#6545](https://github.com/osquery/osquery/pull/6545))

### Documentation

- Update process auditing docs schema link ([#6645](https://github.com/osquery/osquery/pull/6645))
- Improve descriptions for the `processes` table ([#6596](https://github.com/osquery/osquery/pull/6596))
- Replace slackin with Slack shared invite ([#6617](https://github.com/osquery/osquery/pull/6617))
- Update copyright notices to osquery foundation ([#6589](https://github.com/osquery/osquery/pull/6589), [#6590](https://github.com/osquery/osquery/pull/6590))

### Build

- Fix Windows build by removing non existing C11 conformance ([#6629](https://github.com/osquery/osquery/pull/6629))
- Remove `ExecStartPre` from systemd service unit ([#6586](https://github.com/osquery/osquery/pull/6586))
- Fix pip upgrade warning within CI ([#6576](https://github.com/osquery/osquery/pull/6576))
- Detect `MAJOR_IN_SYSMACROS`/`MKDEV` for librpm in CMake ([#6554](https://github.com/osquery/osquery/pull/6554))
- Add `curl_certificate` tests ([#5281](https://github.com/osquery/osquery/pull/5281))
- Update YARA library to 4.0.2 ([#6559](https://github.com/osquery/osquery/pull/6559))
- Improve testing assumptions and flush fsevents when stopping ([#6552](https://github.com/osquery/osquery/pull/6552))
- Fix the test utility to allow Windows profiling ([#6550](https://github.com/osquery/osquery/pull/6550))
- Support ASAN for boost coroutine2 using ucontext ([#6531](https://github.com/osquery/osquery/pull/6531))
- Update instructions for CPack package building ([#6529](https://github.com/osquery/osquery/pull/6529))
- Use specific RPM variables to set the package name ([#6527](https://github.com/osquery/osquery/pull/6527))
- Update compiler version used to v142 within Azure ([#6528](https://github.com/osquery/osquery/pull/6528))

### Hardening

- Restore PIE support being dropped on Linux ([#6611](https://github.com/osquery/osquery/pull/6611))

<a name="4.4.0"></a>
## [4.4.0](https://github.com/osquery/osquery/releases/tag/4.4.0)

[Git Commits](https://github.com/osquery/osquery/compare/4.3.0...4.4.0)

### New Features / Under the Hood improvements

- Implement container access from tables on Linux ([#6209](https://github.com/osquery/osquery/pull/6209), [#6485](https://github.com/osquery/osquery/pull/6485))
- Update language to use 'allow list' and 'deny list' ([#6489](https://github.com/osquery/osquery/pull/6489), [#6487](https://github.com/osquery/osquery/pull/6487), [#6488](https://github.com/osquery/osquery/pull/6488), [#6493](https://github.com/osquery/osquery/pull/6493))
- macos: Automatic configuration of the OpenBSM audit rules ([#6447](https://github.com/osquery/osquery/pull/6447))
- macos: Add polling to OpenBSM publisher ([#6436](https://github.com/osquery/osquery/pull/6436))
- Add messages to distributed query results ([#6352](https://github.com/osquery/osquery/pull/6352))
- Implement event batching support for Windows tables ([#6280](https://github.com/osquery/osquery/pull/6280))

### Table Changes

- Add container access to the os_version table ([#6413](https://github.com/osquery/osquery/pull/6413))
- Add container access to DEB, RPM, NPM packages tables ([#6414](https://github.com/osquery/osquery/pull/6414))
- Add fields auid, fs{u,g}id, s{u,g}id to auditd based tables ([#6362](https://github.com/osquery/osquery/pull/6362))
- Improve apt_sources resiliency ([#6482](https://github.com/osquery/osquery/pull/6482))
- Make file and hash container columns hidden ([#6486](https://github.com/osquery/osquery/pull/6486))
- Add 'maintainer', 'section', 'priority' columns to deb_packages ([#6442](https://github.com/osquery/osquery/pull/6442))
- Add 'vendor', 'package_group' columns to rpm_packages ([#6443](https://github.com/osquery/osquery/pull/6443))
- Add 'arch' column to os_version ([#6444](https://github.com/osquery/osquery/pull/6444))
- Add 'board_xxx' columns to system_info table ([#6398](https://github.com/osquery/osquery/pull/6398))
- Windows: omit non-interactive sessions from logged_in_users ([#6375](https://github.com/osquery/osquery/pull/6375))
- Fixes to package_bom table ([#6457](https://github.com/osquery/osquery/pull/6457), [#6461](https://github.com/osquery/osquery/pull/6461))
- Add chassis_info table for windows ([#5282](https://github.com/osquery/osquery/pull/5282))
- Add Azure tables ([#6507](https://github.com/osquery/osquery/pull/6507))

### Bug Fixes

- Update hash cache inode number in query cache ([#6440](https://github.com/osquery/osquery/pull/6440))
- Only explode registry key if it can be tokenized ([#6474](https://github.com/osquery/osquery/pull/6474))
- Change ErrorBase::takeUnderlyingError to non const ([#6483](https://github.com/osquery/osquery/pull/6483))
- Use RapidJSON to fix event format results and the Kafka Logger ([#6449](https://github.com/osquery/osquery/pull/6449))
- Correct the 'cwd' and 'root' columns of processes table on Windows ([#6459](https://github.com/osquery/osquery/pull/6459))
- Correct some SQLite types ([#6392](https://github.com/osquery/osquery/pull/6392))
- Partial fix for md_devices issue ([#6417](https://github.com/osquery/osquery/pull/6417))
- Fix the handling of empty args strings, on Windows ([#6460](https://github.com/osquery/osquery/pull/6460))
- Refactor shutdown logging, and remove explicit syslog call ([#6376](https://github.com/osquery/osquery/pull/6376))
- Change the Windows registry LIKE path constraint to filter recursively ([#6448](https://github.com/osquery/osquery/pull/6448))
- Use sync resolve within http client ([#6490](https://github.com/osquery/osquery/pull/6490))
- Fix typed_row table caching ([#6508](https://github.com/osquery/osquery/pull/6508))
- Do not use system proxy for AWS local authority ([#6512](https://github.com/osquery/osquery/pull/6512))
- Only populate table cache with star-like selects ([#6513](https://github.com/osquery/osquery/pull/6513))

### Documentation

- Update osquery security policy ([#6425](https://github.com/osquery/osquery/pull/6425))
- Updating changelog for 4.3.0 release ([#6387](https://github.com/osquery/osquery/pull/6387))
- Improve the new table tutorial ([#6479](https://github.com/osquery/osquery/pull/6479))
- Add Auto Table Construction to docs ([#6476](https://github.com/osquery/osquery/pull/6476))
- Add documentation for enabling socket_events on macOS ([#6407](https://github.com/osquery/osquery/pull/6407))
- Update winbaseobj table description ([#6429](https://github.com/osquery/osquery/pull/6429))
- Fixing the description of failed_login_count from account_policy_data ([#6415](https://github.com/osquery/osquery/pull/6415))
- Remove references to brew in macOS install ([#6494](https://github.com/osquery/osquery/pull/6494))
- Add note to bump the Homebrew cask ([#6519](https://github.com/osquery/osquery/pull/6519))
- Updating docs on cpack usage to include Chocolatey ([#6022](https://github.com/osquery/osquery/pull/6022))
- Changelog for 4.4.0 ([#6492](https://github.com/osquery/osquery/pull/6492), [#6523](https://github.com/osquery/osquery/pull/6523)))

### Build

- Fix Userassist.test_sanity test sometimes failing ([#6396](https://github.com/osquery/osquery/pull/6396))
- Drop the facebook and source_migration layers ([#6473](https://github.com/osquery/osquery/pull/6473))
- Move ssdeep-cpp to source_migration ([#6464](https://github.com/osquery/osquery/pull/6464))
- Move smartmontools to source_migration ([#6465](https://github.com/osquery/osquery/pull/6465))
- Build augeas from source on macOS ([#6399](https://github.com/osquery/osquery/pull/6399))
- Build lldpd from source on macOS ([#6406](https://github.com/osquery/osquery/pull/6406))
- Build linenoise-ng from source on macOS and Windows ([#6412](https://github.com/osquery/osquery/pull/6412))
- Build sleuthkit from source on macOS ([#6416](https://github.com/osquery/osquery/pull/6416))
- Build popt from source on macOS ([#6409](https://github.com/osquery/osquery/pull/6409))
- Fix libelfin build on ossfuzz and LLVM/Clang 10 ([#6472](https://github.com/osquery/osquery/pull/6472))
- Use the patched libelfin version ([#6480](https://github.com/osquery/osquery/pull/6480))
- codegen: Port Jinja2 to Templite ([#6470](https://github.com/osquery/osquery/pull/6470))
- Pass the minimum macOS SDK version to openssl only if explicitly set ([#6471](https://github.com/osquery/osquery/pull/6471))
- Add git-lfs as dep for macOS build in documentation ([#6384](https://github.com/osquery/osquery/pull/6384))
- Update openssl from 1.1.1f to 1.1.1g ([#6432](https://github.com/osquery/osquery/pull/6432))
- Build openssl with the macOS SDK version taken from CMake ([#6469](https://github.com/osquery/osquery/pull/6469))
- Do not install openssl docs ([#6441](https://github.com/osquery/osquery/pull/6441))
- Update build configuration of ReadTheDocs ([#6434](https://github.com/osquery/osquery/pull/6434), [#6456](https://github.com/osquery/osquery/pull/6456))
- Link librdkafka on Windows ([#6454](https://github.com/osquery/osquery/pull/6454))
- Build sleuthkit on Windows ([#6445](https://github.com/osquery/osquery/pull/6445))
- Add nupkg cpack build option and update Windows deployment script ([#6262](https://github.com/osquery/osquery/pull/6262))
- Fix rpm and deb package name format ([#6468](https://github.com/osquery/osquery/pull/6468))
- Fix atom_packages, processes, rpm_packages tests ([#6518](https://github.com/osquery/osquery/pull/6518))
- Fixes and cleanup for Windows compiler flags ([#6521](https://github.com/osquery/osquery/pull/6521))
- Correct macOS framework linking ([#6522](https://github.com/osquery/osquery/pull/6522))

### Security Issues

- Disable openssl compression support ([#6433](https://github.com/osquery/osquery/pull/6433))

### Hardening

- Use LOAD_LIBRARY_SEARCH_SYSTEM32 for LoadLibrary ([#6458](https://github.com/osquery/osquery/pull/6458))

<a name="4.3.0"></a>
## [4.3.0](https://github.com/osquery/osquery/releases/tag/4.3.0)

[Git Commits](https://github.com/osquery/osquery/compare/4.2.0...4.3.0)

### New Features / Under the Hood improvements

- Change verbosity of scheduled query execution messages from INFO to verbose only ([#6271](https://github.com/osquery/osquery/pull/6271))
- Updated the unwanted-chrome-extensions queries to include all users, not the osquery process owner only ([#6265](https://github.com/osquery/osquery/pull/6265))
- Check for errors in the return status of the extension tables and report them ([#6108](https://github.com/osquery/osquery/pull/6108))
- First steps to properly support UTF8 strings on Windows ([#6190](https://github.com/osquery/osquery/pull/6190))
- Display the undelying API error string when udev monitoring fails ([#6186](https://github.com/osquery/osquery/pull/6186))
- Add the `path` column to the ATC generate specs ([#6278](https://github.com/osquery/osquery/pull/6278))
- Add Kafka support to Microsoft Windows ([#6095](https://github.com/osquery/osquery/pull/6095))
- Log a warning message if osquery fails to get the service description on Microsoft Windows ([#6281](https://github.com/osquery/osquery/pull/6281))
- Make AWS kinesis status logging configurable ([#6135](https://github.com/osquery/osquery/pull/6135))
- Add an integration test for the `disk_info` table ([#6323](https://github.com/osquery/osquery/pull/6323))
- Use -1 for missing `ppid` in the `process_events` table ([#6339](https://github.com/osquery/osquery/pull/6339))
- Remove error when converting empty numeric rows ([#6371](https://github.com/osquery/osquery/pull/6371))
- Change verbosity from ERROR to INFO of access failures to system processes on Microsoft Windows ([#6370](https://github.com/osquery/osquery/pull/6370))
- Make possible to get verbose messages from the dispatcher service management on Microsoft Windows too ([#6369](https://github.com/osquery/osquery/pull/6369))

### Build

- Fix codegen template for extension group ([#6244](https://github.com/osquery/osquery/pull/6244))
- Update SQLite from 3.30.1-1 to 3.31.1 ([#6252](https://github.com/osquery/osquery/pull/6252))
- Update the osquery-toolchain to version 1.1.0 which uses LLVM/Clang 9.0.1 ([#6315](https://github.com/osquery/osquery/pull/6315))
- Update openssl to version 1.1.1f ([#6302](https://github.com/osquery/osquery/pull/6302), [#6359](https://github.com/osquery/osquery/pull/6359))
- Simplify formula-based third party libraries build ([#6303](https://github.com/osquery/osquery/pull/6303))
- Removed the Buck build system ([#6361](https://github.com/osquery/osquery/pull/6361))

### Bug Fixes

- Fix CFNumber conversion when the type was a Float64/32 instead of a Double ([#6273](https://github.com/osquery/osquery/pull/6273))
- Fix duplicate results being returned by the chrome_extensions table ([#6277](https://github.com/osquery/osquery/pull/6277))
- Fix flaky ProcessOpenFilesTest.test_sanity ([#6185](https://github.com/osquery/osquery/pull/6185))
- Fix the `--database_dump` flag for RocksDB not outputting anything ([#6272](https://github.com/osquery/osquery/pull/6272))
- Fix the `pci_devices` table pci ids extraction in non-existing paths ([#6297](https://github.com/osquery/osquery/pull/6297))
- Fix parsing an invalid decorators config ([#6317](https://github.com/osquery/osquery/pull/6317))
- Fix flaky TLSConfigTests.test_runner_and_scheduler ([#6308](https://github.com/osquery/osquery/pull/6308))
- Fix chromeExtensions.test_sanity ([#6324](https://github.com/osquery/osquery/pull/6324))
- Fix broken Unicode filename searches on Microsoft Windows ([#6291](https://github.com/osquery/osquery/pull/6291))
- Fix a use-after-free when sqlite attempts to access the entire rows data at the end of a query ([#6328](https://github.com/osquery/osquery/pull/6328))
- Keep proc instance for test_base and test_osqueryd ([#6335](https://github.com/osquery/osquery/pull/6335))
- Fix osquery not exiting when given check or dump requests ([#6334](https://github.com/osquery/osquery/pull/6334))
- Fix `process` table `cmdline` parsing ([#6340](https://github.com/osquery/osquery/pull/6340))
- Fix a crash when parsing files with libmagic ([#6363](https://github.com/osquery/osquery/pull/6363))
- Fix a sporadic readFile API failure when using non-blocking I/O ([#6368](https://github.com/osquery/osquery/pull/6368))
- Fix the MSI package not always installing in the system drive by default ([#6379](https://github.com/osquery/osquery/pull/6379))
- Ensure the extensions uuid is never 0 ([#6377](https://github.com/osquery/osquery/pull/6377))
- Fix a race condition making the watcher act as a worker on Microsoft Windows ([#6372](https://github.com/osquery/osquery/pull/6372))
- Fix extensions tables detaching which was sometimes failing ([#6373](https://github.com/osquery/osquery/pull/6373))
- Fix an issue with extensions re-registration ([#6374](https://github.com/osquery/osquery/pull/6374))
- Fix a crash due to a race condition in accessing the iokit port on Darwin (Apple OS X) ([#6380](https://github.com/osquery/osquery/pull/6380))

### Hardening

- Limit SQL functions regex_match and regex_split regex size ([#6267](https://github.com/osquery/osquery/pull/6267))
- Prevent a stack overflow when parsing deeply nested configs ([#6325](https://github.com/osquery/osquery/pull/6325))

### Table Changes

- Added table `chrome_extension_content_scripts` to All Platforms ([#6140](https://github.com/osquery/osquery/pull/6140))
- Added table `docker_container_fs_changes` to POSIX-compatible Platforms ([#6178](https://github.com/osquery/osquery/pull/6178))
- Added table `windows_security_center` to Microsoft Windows ([#6256](https://github.com/osquery/osquery/pull/6256))
- Added many new tables to Linux to query `lxd` ([#6249](https://github.com/osquery/osquery/pull/6249))
- Added table `screenlock` to Darwin (Apple OS X) ([#6243](https://github.com/osquery/osquery/pull/6243))
- Added table `userassist` to Microsoft Windows ([#5539](https://github.com/osquery/osquery/pull/5539))
- Added column `status` (`TEXT`) to table `deb_packages` ([#6341](https://github.com/osquery/osquery/pull/6341))
- Added many new columns to the `curl_certificate` table ([#6176](https://github.com/osquery/osquery/pull/6176))
- Added table `socket_events` to Darwin (Apple OS X) ([#6028](https://github.com/osquery/osquery/pull/6028))
- Added table `hvci_status`, previously inadvertly left out from the build, to Microsoft Windows ([#6378](https://github.com/osquery/osquery/pull/6378))

<a name="4.2.0"></a>
## [4.2.0](https://github.com/osquery/osquery/releases/tag/4.2.0)

[Git Commits](https://github.com/osquery/osquery/compare/4.1.2...4.2.0)

### New Features / Under the Hood improvements

- TLS Testing infrastructure has been overhauled ([#6170](https://github.com/osquery/osquery/pull/6170))
- Boost regex has been replaced with std ([#6236](https://github.com/osquery/osquery/pull/6236))
- `community_id_v1` added as a SQL function ([#6211](https://github.com/osquery/osquery/pull/6211))

### Build

- Fix format checking on Windows ([#6188](https://github.com/osquery/osquery/pull/6188))
- Fix format folder exclusions for build checks ([#6201](https://github.com/osquery/osquery/pull/6201))
- Fix the linking for extensions in build ([#6219](https://github.com/osquery/osquery/pull/6219))
- Fix build to include windows optional features table ([#6207](https://github.com/osquery/osquery/pull/6207))

### Security Issues

- [CVE-2020-1887] osquery does not properly verify the SNI hostname ([#6197](https://github.com/osquery/osquery/pull/6197))

### Bug Fixes

- Carver no longer returns empty carves for hidden files ([#6183](https://github.com/osquery/osquery/pull/6183))
- Address a race in the Dispatcher logic ([#6145](https://github.com/osquery/osquery/pull/6145))
- Fix validation in 'last' table ([#6147](https://github.com/osquery/osquery/pull/6147))
- Fix flaky logger testing ([#6171](https://github.com/osquery/osquery/pull/6171))
- Fix JSON format assumptions in file_paths parsing ([#6159](https://github.com/osquery/osquery/pull/6159))
- Fix windows WMI BSTR to be wstrings ([#6175](https://github.com/osquery/osquery/pull/6175))
- Fix windows string <-> wstring conversion functions ([#6187](https://github.com/osquery/osquery/pull/6187))
- Enable more intelligent path expansion on Windows ([#6153](https://github.com/osquery/osquery/pull/6153))
- Fix heap buffer overflow in callDoubleFunc and powerFunc ([#6225](https://github.com/osquery/osquery/pull/6225))

### Table Changes

- Added table `firefox_addons` to All Platforms ([#6200](https://github.com/osquery/osquery/pull/6200))
- Added table `ssh_configs` to All Platforms ([#6161](https://github.com/osquery/osquery/pull/6161))
- Added table `user_ssh_keys` to All Platforms ([#6161](https://github.com/osquery/osquery/pull/6161))
- Added table `mdls` to Darwin (Apple OS X) ([#4825](https://github.com/osquery/osquery/pull/4825))
- Added table `hvci_status` to Microsoft Windows ([#5426](https://github.com/osquery/osquery/pull/5426))
- Added table `ntfs_journal_events` to Microsoft Windows ([#5371](https://github.com/osquery/osquery/pull/5371))
- Added table `docker_image_layers` to POSIX-compatible Platforms ([#6154](https://github.com/osquery/osquery/pull/6154))
- Added table `process_open_pipes` to POSIX-compatible Platforms ([#6142](https://github.com/osquery/osquery/pull/6142))
- Added table `apparmor_profiles` to Ubuntu, CentOS ([#6138](https://github.com/osquery/osquery/pull/6138))
- Added table `selinux_settings` to Ubuntu, CentOS ([#6118](https://github.com/osquery/osquery/pull/6118))
- Added column `lock_status` (`INTEGER_TYPE`) to table `bitlocker_info` ([#6155](https://github.com/osquery/osquery/pull/6155))
- Added column `percentage_encrypted` (`INTEGER_TYPE`) to table `bitlocker_info` ([#6155](https://github.com/osquery/osquery/pull/6155))
- Added column `version` (`INTEGER_TYPE`) to table `bitlocker_info` ([#6155](https://github.com/osquery/osquery/pull/6155))
- Added column `optional_permissions` (`TEXT_TYPE`) to table `chrome_extensions` ([#6115](https://github.com/osquery/osquery/pull/6115))
- Removed table `firefox_addons` from POSIX-compatible Platforms ([#6200](https://github.com/osquery/osquery/pull/6200))
- Removed table `ssh_configs` from POSIX-compatible Platforms ([#6161](https://github.com/osquery/osquery/pull/6161))
- Removed table `user_ssh_keys` from POSIX-compatible Platforms ([#6161](https://github.com/osquery/osquery/pull/6161))

<a name="4.1.2"></a>
## [4.1.2](https://github.com/osquery/osquery/releases/tag/4.1.2)

[Git Commits](https://github.com/osquery/osquery/compare/4.1.1...4.1.2)

### New Features / Under the Hood improvements

- Add more tests throughout the codebase ([#5908](https://github.com/osquery/osquery/pull/5908)), ([#6071](https://github.com/osquery/osquery/pull/6071)), ([#6126](https://github.com/osquery/osquery/pull/6126))
- The `chrome_extensions` table now supports Chromium and Brave ([#6126](https://github.com/osquery/osquery/pull/6126))

### Build

- Require Python 3.5 and greater ([#6081](https://github.com/osquery/osquery/pull/6081)), ([#6120](https://github.com/osquery/osquery/pull/6120))
- Prepare Python tests for CI (lots of effort!) ([#6068](https://github.com/osquery/osquery/pull/6068))
- Restore osqueryd integration test ([#6116](https://github.com/osquery/osquery/pull/6116))

### Bug Fixes

- Continue to use `com.facebook.osquery.plist` for Launch Daemon configuration ([#6093](https://github.com/osquery/osquery/pull/6093))
- Update systemd service to use KillMode=control-group ([#6096](https://github.com/osquery/osquery/pull/6096))
- RPM and DEB packages both have post-install scripts to reload systemd ([#6097](https://github.com/osquery/osquery/pull/6097))
- Update Windows package build script to include cert bundle ([#6114](https://github.com/osquery/osquery/pull/6114))
- Update table specs to fix constraints passing ([#6103](https://github.com/osquery/osquery/pull/6103)), ([#6104](https://github.com/osquery/osquery/pull/6104)), ([#6105](https://github.com/osquery/osquery/pull/6105)), ([#6106](https://github.com/osquery/osquery/pull/6106)), ([#6122](https://github.com/osquery/osquery/pull/6122))

### Table Changes

- Added tables `azure_instance_tags` and `azure_instance_metadata` to Linux and Microsoft Windows ([#5434](https://github.com/osquery/osquery/pull/5434))
- Added column `install_time` (`INTEGER_TYPE`) to table `rpm_packages` ([#6113](https://github.com/osquery/osquery/pull/6113))
- Added column `bsd_flags` (`TEST_TYPE`) to table `file` on Darwin ([#5981](https://github.com/osquery/osquery/pull/5981))

<a name="4.1.1"></a>
## [4.1.1](https://github.com/osquery/osquery/releases/tag/4.1.1)

[Git Commits](https://github.com/osquery/osquery/compare/4.1.0...4.1.1)

### New Features / Under the Hood improvements

- Improve `nvram` table to use input variable names ([#6053](https://github.com/osquery/osquery/pull/6053))
- Improve `apt_sources` source detection ([#6047](https://github.com/osquery/osquery/pull/6047))
- Change `atom_packages` to use user constraints ([#6052](https://github.com/osquery/osquery/pull/6052))
- Re-enable required-column warning messages ([#6038](https://github.com/osquery/osquery/pull/6038))

### Build

- Migrate several libraries to the CMake source layer ([#5902](https://github.com/osquery/osquery/pull/5902)), ([#6023](https://github.com/osquery/osquery/pull/6023))
- Update SQLite from 3.29.0-3 to 3.30.1-1 ([#6020](https://github.com/osquery/osquery/pull/6020))
- Recommend building with MacOS 10.11 SDK ([#6000](https://github.com/osquery/osquery/pull/6000))

### Bug Fixes

- Fix Linux audit incorrect read and handle leak ([#5959](https://github.com/osquery/osquery/pull/5959))
- Change "logNumericsAsNumbers" to "numerics" logger top-level key ([#6002](https://github.com/osquery/osquery/pull/6002))
- Restore INDEX behavior for extensions ([#6006](https://github.com/osquery/osquery/pull/6006))
- Fix potential JSON parsing issues in ATC plugin ([#6029](https://github.com/osquery/osquery/pull/6029))
- Avoid scanning special files with YARA ([#5971](https://github.com/osquery/osquery/pull/5971))
- Fix use-after-move in YARA subscriber ([#6054](https://github.com/osquery/osquery/pull/6054))
- Handle relative redirects in internal HTTP clients ([#6049](https://github.com/osquery/osquery/pull/6049))
- Apply options config parsing before others ([#6050](https://github.com/osquery/osquery/pull/6050))

### Table Changes

- Added table `windows_optional_features` to Microsoft Windows [#5991](https://github.com/osquery/osquery/pull/5991))

<a name="4.1.0"></a>
## [4.1.0](https://github.com/osquery/osquery/releases/tag/4.1.0)

[Git Commits](https://github.com/osquery/osquery/compare/4.0.2...4.1.0)

### New Features / Under the Hood improvements

- Restore extension SDK and build support ([#5851](https://github.com/osquery/osquery/pull/5851))
- Documentation improvements ([#5860](https://github.com/osquery/osquery/pull/5860)), ([#5852](https://github.com/osquery/osquery/pull/5852)), ([#5912](https://github.com/osquery/osquery/pull/5912)), ([#5954](https://github.com/osquery/osquery/pull/5954))
- Add more tests throughout the codebase ([#5837](https://github.com/osquery/osquery/pull/5837)), ([#5832](https://github.com/osquery/osquery/pull/5832)), ([#5857](https://github.com/osquery/osquery/pull/5857)), ([#5864](https://github.com/osquery/osquery/pull/5864)), ([#5855](https://github.com/osquery/osquery/pull/5855)), ([#5869](https://github.com/osquery/osquery/pull/5869)), ([#5871](https://github.com/osquery/osquery/pull/5871)), ([#5885](https://github.com/osquery/osquery/pull/5885)), ([#5903](https://github.com/osquery/osquery/pull/5903)), ([#5879](https://github.com/osquery/osquery/pull/5879)), ([#5914](https://github.com/osquery/osquery/pull/5914)), ([#5941](https://github.com/osquery/osquery/pull/5941)), ([#5957](https://github.com/osquery/osquery/pull/5957))
- Allow configuration more Linux Audit settings using flags ([#5953](https://github.com/osquery/osquery/pull/5953))
- Add logger_tls_max_lines flag ([#5956](https://github.com/osquery/osquery/pull/5956))
- Add AWS Session Token support ([#5944](https://github.com/osquery/osquery/pull/5944))

### Build

- Lots of work on CPack-based packaging ([#5809](https://github.com/osquery/osquery/pull/5809)), ([#5822](https://github.com/osquery/osquery/pull/5822)), ([#5823](https://github.com/osquery/osquery/pull/5823)), ([#5827](https://github.com/osquery/osquery/pull/5827)), ([#5780](https://github.com/osquery/osquery/pull/5780)), ([#5850](https://github.com/osquery/osquery/pull/5850)), ([#5843](https://github.com/osquery/osquery/pull/5843)), ([#5881](https://github.com/osquery/osquery/pull/5881)), ([#5825](https://github.com/osquery/osquery/pull/5825)), ([#5940](https://github.com/osquery/osquery/pull/5940)), ([#5951](https://github.com/osquery/osquery/pull/5951)), ([#5936](https://github.com/osquery/osquery/pull/5936))
- Lots of work porting Python2 to Python3 ([#5846](https://github.com/osquery/osquery/pull/5846))
- Upgrade OpenSSL to 1.0.2t on all platforms ([#5928](https://github.com/osquery/osquery/pull/5928))
- Use SQLite 3.29.0 on Windows and macOS ([#5810](https://github.com/osquery/osquery/pull/5810))
- Use aws-sdk-cpp source-builds on Windows and macOS ([#5889](https://github.com/osquery/osquery/pull/5889))
- Add various code quality checks and utilities ([#5834](https://github.com/osquery/osquery/pull/5834)), ([#5730](https://github.com/osquery/osquery/pull/5730)), ([#5872](https://github.com/osquery/osquery/pull/5872))

### Hardening

- Restore fuzzing harness and use oss-fuzz ([#5844](https://github.com/osquery/osquery/pull/5844)), ([#5886](https://github.com/osquery/osquery/pull/5886)), ([#5910](https://github.com/osquery/osquery/pull/5910)), ([#5915](https://github.com/osquery/osquery/pull/5915)), ([#5923](https://github.com/osquery/osquery/pull/5923)), ([#5955](https://github.com/osquery/osquery/pull/5955)), ([#5963](https://github.com/osquery/osquery/pull/5963))
- Use newer RapidJSON and switch to safer iterative parsing ([#5893](https://github.com/osquery/osquery/pull/5893)), ([#5913](https://github.com/osquery/osquery/pull/5913))

### Bug Fixes

- Set Windows MSI ErrorControl to normal instead of critical ([#5818](https://github.com/osquery/osquery/pull/5818))
- Wrap flagfile with quotes for Windows install flag ([#5824](https://github.com/osquery/osquery/pull/5824))
- Improve submodule usages in CMake ([#5850](https://github.com/osquery/osquery/pull/5850)), ([#5880](https://github.com/osquery/osquery/pull/5880)), ([#5892](https://github.com/osquery/osquery/pull/5892)), ([#5897](https://github.com/osquery/osquery/pull/5897)), ([#5907](https://github.com/osquery/osquery/pull/5907))
- Improve locking support in internal APIs ([#5841](https://github.com/osquery/osquery/pull/5841)), ([#5906](https://github.com/osquery/osquery/pull/5906)), ([#5943](https://github.com/osquery/osquery/pull/5943)), ([#5944](https://github.com/osquery/osquery/pull/5944))
- Fixes for macOS application layer firewall tables ([#5378](https://github.com/osquery/osquery/pull/5378))
- Fixes within BPF event tables ([#5874](https://github.com/osquery/osquery/pull/5874))
- Refactor and improve PCI device tables on Linux ([#5446](https://github.com/osquery/osquery/pull/5446))
- Implement PID indexing on Windows `processes` table ([#5919](https://github.com/osquery/osquery/pull/5919))
- Improve `WHERE IN()` performance ([#5924](https://github.com/osquery/osquery/pull/5924)), ([#5938](https://github.com/osquery/osquery/pull/5938))
- Improve the internal HTTP client ([#5891](https://github.com/osquery/osquery/pull/5891)), ([#5946](https://github.com/osquery/osquery/pull/5946)), ([#5947](https://github.com/osquery/osquery/pull/5947))
- Fix Windows version codename lookup ([#5887](https://github.com/osquery/osquery/pull/5887))

### Table Changes

- Added table `alf_services` to Darwin (Apple OS X) ([#5378](https://github.com/osquery/osquery/pull/5378))
- Added table `connectivity` to Microsoft Windows ([#5500](https://github.com/osquery/osquery/pull/5500))
- Added table `default_environment` to Microsoft Windows ([#5441](https://github.com/osquery/osquery/pull/5441))
- Added table `windows_security_products` to Microsoft Windows ([#5479](https://github.com/osquery/osquery/pull/5479))
- Added column `platform_mask` (`INTEGER_TYPE`) to table `osquery_info` ([#5898](https://github.com/osquery/osquery/pull/5898))

<a name="4.0.2"></a>
## [4.0.2](https://github.com/osquery/osquery/releases/tag/4.0.2)

This release fixes crashes identified in 4.0.1. There are no changes in functionality.

[Git Commits](https://github.com/osquery/osquery/compare/4.0.1...4.0.2)

### Bug Fixes

- Fix configuration of AWS libraries to address crash in Linux ([#5799](https://github.com/osquery/osquery/pull/5799))
- Remove RocksDB optimization causing crash ([#5797](https://github.com/osquery/osquery/pull/5797))

<a name="4.0.1"></a>
## [4.0.1](https://github.com/osquery/osquery/releases/tag/4.0.1)

This release has two major focuses. It is the first release since [osquery transitioned to a Linux Foundation project](https://www.linuxfoundation.org/press-release/2019/06/the-linux-foundation-announces-intent-to-form-new-foundation-to-support-osquery-community/).

It features a heavily reworked build system. This aims to provide flexibility and stability.

[Git Commits](https://github.com/osquery/osquery/compare/3.3.2...4.0.1)

### New Features / Under the Hood improvements

- Linux Audit `process_events` Implement support for fork/vfork/clone/execveat ([#5701](https://github.com/osquery/osquery/pull/5701))
- New SQLite function `regex_match` to match across columns ([#5444](https://github.com/osquery/osquery/pull/5444))
- LRU cache for syscall tracing ([#5521](https://github.com/osquery/osquery/pull/5521))
- Basic tracing via eBPF on Linux ([#5403](https://github.com/osquery/osquery/pull/5403), [#5386](https://github.com/osquery/osquery/pull/5386), [#5384](https://github.com/osquery/osquery/pull/5384))
- Experimental `kill` and `setuid` syscall tracing in Linux via eBPF ([#5519](https://github.com/osquery/osquery/pull/5519))
- New eventing (ev2) framework ([#5401](https://github.com/osquery/osquery/pull/5401))
- Improved table performance profiles ([#5187](https://github.com/osquery/osquery/pull/5187))
- macOS query pack: detect SearchAwesome malware ([#5713](https://github.com/osquery/osquery/pull/5713))
- macOS query pack: detect when a process is tapping keyboard event ([#5345](https://github.com/osquery/osquery/pull/5345))

### Build

- Refactor CMake build ([#5604](https://github.com/osquery/osquery/pull/5604), [#5627](https://github.com/osquery/osquery/pull/5627), [#5630](https://github.com/osquery/osquery/pull/5630), ([#5618](https://github.com/osquery/osquery/pull/5618)), ([#5619](https://github.com/osquery/osquery/pull/5619)))
- Refactor third-party libraries to build from source on Linux ([#5706](https://github.com/osquery/osquery/pull/5706))
- Add Azure Pipelines support for CI/CD ([#5604](https://github.com/osquery/osquery/pull/5604), [#5632](https://github.com/osquery/osquery/pull/5632), [#5626](https://github.com/osquery/osquery/pull/5626), [#5613](https://github.com/osquery/osquery/pull/5613), [#5607](https://github.com/osquery/osquery/pull/5607), [#5673](https://github.com/osquery/osquery/pull/5673), [#5610](https://github.com/osquery/osquery/pull/5610))
- Add Buck as a build system ([971bee44](https://github.com/osquery/osquery/commit/971bee44))
- Use `urllib2` to automatically handle HTTP 301/302 redirections ([#5612](https://github.com/osquery/osquery/pull/5612))
- Update MSI package to install to `Program Files` on Windows ([#5579](https://github.com/osquery/osquery/pull/5579))
- Linux custom toolchain integration ([#5759](https://github.com/osquery/osquery/pull/5759))

### Hardening

- Link binaries with Full RELRO on Linux ([#5748](https://github.com/osquery/osquery/pull/5748))
- Remove FTS features from SQLite ([#5703](https://github.com/osquery/osquery/pull/5703), [#5702](https://github.com/osquery/osquery/issues/5702))
- Fix SQLite API usage errors ([#5551](https://github.com/osquery/osquery/pull/5551))
- Fix issues reported by ASAN ([#5665](https://github.com/osquery/osquery/pull/5665))
- Handle bad FDs in `md_tables` ([#5553](https://github.com/osquery/osquery/pull/5533))
- Fix lock resource leak in events/syslog ([#5552](https://github.com/osquery/osquery/pull/5552))
- Fix memory leak in macOS `keychain_items` and `extended_attributes` tables ([#5550](https://github.com/osquery/osquery/pull/5550), [#5538](https://github.com/osquery/osquery/pull/5538))
- Fix memory leak in `genLoggedInUsers` (Windows). Update `WTSFreeMemoryEx` to `WTSFreeMemory` ([#5642](https://github.com/osquery/osquery/pull/5642))
- Fix potential null dereferences in `smbios_tables` ([#5332](https://github.com/osquery/osquery/pull/5332))
- Fix osquery exiting with wrong status ([3824c2e6](https://github.com/osquery/osquery/commit/3824c2e6))
- Add additional `install` and `uninstall` flag incompatibility check ([85eb77a0](https://github.com/osquery/osquery/commit/85eb77a0))
- Fix warning with constants initialisation in `magic` ([2a624f2f](https://github.com/osquery/osquery/commit/2a624f2f))
- Fix sign compare warning in `file_compression` ([b93069b3](https://github.com/osquery/osquery/commit/b93069b3))
- Refactored `logical_drives` table on Windows ([#5400](https://github.com/osquery/osquery/pull/5400))
- Refactored core/windows/wmi to use smart pointers ([#5492](https://github.com/osquery/osquery/pull/5492))
- Fixed various potential crashes in the virtual table implementation ([6ade85a5](https://github.com/osquery/osquery/commit/6ade85a5))
- Increase the amount of `MaxRecvRetries` for Thrift sockets ([#5390](https://github.com/osquery/osquery/pull/5390))


### Bug Fixes

- Fix the reading of the serial of a certificate (little-endian big int) ([#5742](https://github.com/osquery/osquery/pull/5742))
- Fix bugs and update pathname variables in MSI package build script ([#5733](https://github.com/osquery/osquery/pull/5733))
- Fix `registry` table exception closing an uninitialized key handle ([#5718](https://github.com/osquery/osquery/pull/5718))
- Config views are now recreated on startup ([#5732](https://github.com/osquery/osquery/pull/5732))
- Change MSI Service Error handling on Windows ([#5467](https://github.com/osquery/osquery/pull/5467))
- Allow mounting SQLite DBs using WAL journaling with ATC ([#5525](https://github.com/osquery/osquery/issues/5225), [#5633](https://github.com/osquery/osquery/pull/5633))
- Fix `mount` table interacting with direct autofs ([#5635](https://github.com/osquery/osquery/pull/5635))
- Fix HTTP Host Header to include port ([#5576](https://github.com/osquery/osquery/pull/5576))
- Various fixes to the Windows `certificates` table and expansion to include Personal certificates ([#5697](https://github.com/osquery/osquery/pull/5697)), ([#5696](https://github.com/osquery/osquery/pull/5696)), ([#5640](https://github.com/osquery/osquery/pull/5640)), ([#5631](https://github.com/osquery/osquery/pull/5631))
- Add optimization back to macOS `users` and `groups` ([#5684](https://github.com/osquery/osquery/pull/5684))
- Do not return a row for macOS `battery` if no data is present ([#5650](https://github.com/osquery/osquery/pull/5650))
- Fix several integer conversions in `process_ops` ([#5614](https://github.com/osquery/osquery/pull/5614))
- Include weekends on the `kernel_panics` table ([#5298](https://github.com/osquery/osquery/pull/5298))
- Fix `key_strength` bug for Windows `certificates` table ([#5304](https://github.com/osquery/osquery/pull/5304))
- The `interface` column of `routes` table could be empty on Windows ([bcf0ab8e](https://github.com/osquery/osquery/commit/bcf0ab8e))
- The `name` column of `programs` table could be empty on Windows ([7bceba4b](https://github.com/osquery/osquery/commit/7bceba4b))
- Fix `disable_watcher` flag ([08dc11b7](https://github.com/osquery/osquery/commit/08dc11b7))
- Populate `path` column correctly in `firefox_addons` table ([#5462](https://github.com/osquery/osquery/pull/5462))
- Fix numeric monitoring plugin not being registered ([#5484](https://github.com/osquery/osquery/pull/5484))
- Fix wrong error code returned when querying the Windows registry ([#5621](https://github.com/osquery/osquery/pull/5621))
- Fix `logical_drives` boot partition detection ([#5477](https://github.com/osquery/osquery/pull/5477))
- Replace sync calls by async within the HTTP client implementation ([#5606](https://github.com/osquery/osquery/pull/5606))
- Fix RocksDB crash related to `OptimizeForSmallDb` ([a31d7582](https://github.com/osquery/osquery/commit/a31d7582))
- Fix bug in table column data validator ([e3037331](https://github.com/osquery/osquery/commit/e3037331))
- Fix random port problem ([a32ed7c4](https://github.com/osquery/osquery/commit/a32ed7c4))
- Refactor `battery` table and return information even if advanced information is missing ([6a64e353](https://github.com/osquery/osquery/commit/6a64e353))


### Table Changes

- Added table `ibridge_info` on macOS (Notebooks only) ([#5707](https://github.com/osquery/osquery/pull/5707))
- Added table `running_apps` on macOS ([#5216](https://github.com/osquery/osquery/pull/5216))
- Added table `atom_packages` on macOS and Linux ([6d159d40](https://github.com/osquery/osquery/commit/6d159d40))
- Remove EC2 tables on Windows ([#5657](https://github.com/osquery/osquery/pull/5657))
- Add column `win_timestamp` to `time` table on Windows ([3bbe6c51](https://github.com/osquery/osquery/commit/3bbe6c51))
- Add column `is_hidden` to `users` and `groups` table on macOS ([#5368](https://github.com/osquery/osquery/pull/5368))
- Add column `profile` to `chrome_extensions` table ([#5213](https://github.com/osquery/osquery/pull/5213))
- Add column `epoch` to `rpm_packages` table on Linux ([#5248](https://github.com/osquery/osquery/pull/5248))
- Add column `sid` to `logged_in_users` table on Windows ([#5454](https://github.com/osquery/osquery/pull/5454))
- Add column `registry_hive` to `logged_in_users` table on Windows ([#5454](https://github.com/osquery/osquery/pull/5454))
- Add column `sid` to `certificates` table on Windows ([#5631](https://github.com/osquery/osquery/pull/5631))
- Add column `store_location` to `certificates` table on Windows ([#5631](https://github.com/osquery/osquery/pull/5631))
- Add column `store` to `certificates` table on Windows ([#5631](https://github.com/osquery/osquery/pull/5631))
- Add column `username` to `certificates` table on Windows ([#5631](https://github.com/osquery/osquery/pull/5631))
- Add column `store_id` to `certificates` table on Windows ([#5631](https://github.com/osquery/osquery/pull/5631))
- Add column `product_version`  to `file` table on Windows ([#5431](https://github.com/osquery/osquery/pull/5431))
- Add column `source` to `sudoers` table on POSIX systems ([#5350](https://github.com/osquery/osquery/pull/5350))
