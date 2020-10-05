# osquery Changelog

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
- Added table `docker_container_fs_changes` to POSIX-compatible Plaforms ([#6178](https://github.com/osquery/osquery/pull/6178))
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
- Added table `docker_image_layers` to POSIX-compatible Plaforms ([#6154](https://github.com/osquery/osquery/pull/6154))
- Added table `process_open_pipes` to POSIX-compatible Plaforms ([#6142](https://github.com/osquery/osquery/pull/6142))
- Added table `apparmor_profiles` to Ubuntu, CentOS ([#6138](https://github.com/osquery/osquery/pull/6138))
- Added table `selinux_settings` to Ubuntu, CentOS ([#6118](https://github.com/osquery/osquery/pull/6118))
- Added column `lock_status` (`INTEGER_TYPE`) to table `bitlocker_info` ([#6155](https://github.com/osquery/osquery/pull/6155))
- Added column `percentage_encrypted` (`INTEGER_TYPE`) to table `bitlocker_info` ([#6155](https://github.com/osquery/osquery/pull/6155))
- Added column `version` (`INTEGER_TYPE`) to table `bitlocker_info` ([#6155](https://github.com/osquery/osquery/pull/6155))
- Added column `optional_permissions` (`TEXT_TYPE`) to table `chrome_extensions` ([#6115](https://github.com/osquery/osquery/pull/6115))
- Removed table `firefox_addons` from POSIX-compatible Plaforms ([#6200](https://github.com/osquery/osquery/pull/6200))
- Removed table `ssh_configs` from POSIX-compatible Plaforms ([#6161](https://github.com/osquery/osquery/pull/6161))
- Removed table `user_ssh_keys` from POSIX-compatible Plaforms ([#6161](https://github.com/osquery/osquery/pull/6161))

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
- Fixed various potential crashes in the virtual table implementaion ([6ade85a5](https://github.com/osquery/osquery/commit/6ade85a5))
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
