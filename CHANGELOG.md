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
- Added table `ntfs_journal_events` to Microsoft Windows ([#5426](https://github.com/osquery/osquery/pull/5426))
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
- Update MSI package to install to `Program Files` on Windows ([#5579](https://github.com/osquery/osquery/pull/54579))
- Linux custom toolchain integration ([#5759](https://github.com/osquery/osquery/pull/5759))


### Harderning

- Link binaries with Full RELRO on Linux ([#5748](https://github.com/osquery/osquery/pull/5748))
- Remove FTS features from SQLite ([#5703](https://github.com/osquery/osquery/pull/5703)) ([#5702](https://github.com/osquery/osquery/issues/5702))
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
- Added column `win_timestamp` to `time` table on Windows ([3bbe6c51](https://github.com/osquery/osquery/commit/3bbe6c51))
- Added column `is_hidded` to `users` and `groups` table on macOS ([#5368](https://github.com/osquery/osquery/pull/5368))
- Added column `profile` to `chrome_extensions` table ([#5213](https://github.com/osquery/osquery/pull/5213))
- Added column `epoch` to `rpm_packages` table on Linux ([#5248](https://github.com/osquery/osquery/pull/5248))
- Added column `sid` to `logged_in_users` table on Windows ([#5454](https://github.com/osquery/osquery/pull/5454))
- Added column `registry_hive` to `logged_in_users` table on Windows ([#5454](https://github.com/osquery/osquery/pull/5454))
- Added column `sid` to `certificates` table on Windows ([#5631](https://github.com/osquery/osquery/pull/5631))
- Added column `store_location` to `certificates` table on Windows ([#5631](https://github.com/osquery/osquery/pull/5631))
- Added column `store` to `certificates` table on Windows ([#5631](https://github.com/osquery/osquery/pull/5631))
- Added column `username` to `certificates` table on Windows ([#5631](https://github.com/osquery/osquery/pull/5631))
- Added column `store_id` to `certificates` table on Windows ([#5631](https://github.com/osquery/osquery/pull/5631))
- Added column `product_version`  to `file` table on Windows ([#5431](https://github.com/osquery/osquery/pull/5431))
- Added column `source` to `sudoers` table on POSIX systems ([#5350](https://github.com/osquery/osquery/pull/5350))
