<a name="4.0.1"></a>
## [4.0.1](https://github.com/osquery/osquery/releases/tag/4.0.1)

This release has two major focuses.  It is first release since [osquery transitioned to being part of the linux foundation](https://www.linuxfoundation.org/press-release/2019/06/the-linux-foundation-announces-intent-to-form-new-foundation-to-support-osquery-community/).

It features a heavily reworked build system. This aims to provide flexibility and stability. 

[Git Commits](https://github.com/osquery/osquery/compare/3.3.2...4.0.1)


### New Features / Under the Hood improvements

Audit — `process_events` Implement support for fork/vfork/clone/execveat ([#5701](https://github.com/osquery/osquery/pull/5701))

New SQLite function `regex_match` to match across columns ([#5444](https://github.com/osquery/osquery/pull/5444))

macOS query pack: detect SearchAwesome malware ([#5713](https://github.com/osquery/osquery/pull/5713))

macOS query pack: detect when a process is tapping keyboard event ([#5345](https://github.com/osquery/osquery/pull/5345))

LRU cache for syscall tracing ([#5521](https://github.com/osquery/osquery/pull/5521))

Basic tracing via eBPF on Linux (#5403, #5386, #5384) 

Experimental `kill` and `setuid` syscall tracing in Linux via eBPF ([#5519](https://github.com/osquery/osquery/pull/5519))

New eventing (ev2) framework ([#5401](https://github.com/osquery/osquery/pull/5401))

Increase the amount of MaxRecvRetries for thrift socket (#5390)

Added CodeProfiler

### Build

Add CMake support ([#5604](https://github.com/osquery/osquery/pull/5604), [#5627](https://github.com/osquery/osquery/pull/5627), [#5630](https://github.com/osquery/osquery/pull/5630))

Add Azure Pipelines support for CI/CD ([#5604](https://github.com/osquery/osquery/pull/5604), [#5632](https://github.com/osquery/osquery/pull/5632), [#5626](https://github.com/osquery/osquery/pull/5626), [#5613](https://github.com/osquery/osquery/pull/5613), [#5607](https://github.com/osquery/osquery/pull/5607), [#5673](https://github.com/osquery/osquery/pull/5673), [#5610](https://github.com/osquery/osquery/pull/5610))

Add BUCK as a build system ([971bee44](https://github.com/osquery/osquery/commit/971bee44))

Fix buck builds ([#5647](https://github.com/osquery/osquery/pull/5647), [#5623](https://github.com/osquery/osquery/pull/5623))

Use `urllib2` to automatically handle HTTP 301/302 redirections ([#5612](https://github.com/osquery/osquery/pull/5612))

Fix detection of some headers on some IDEs ([#5619](https://github.com/osquery/osquery/pull/5619))

Fix prepare_for_ide target on macOS and Windows ([#5618](https://github.com/osquery/osquery/pull/5618))

Update MSI package to install to `Program Files` on Windows ([#5579](https://github.com/osquery/osquery/pull/54579))

### Harderning

sqlite: Remove FTS features from sqlite ([#5703](https://github.com/osquery/osquery/pull/5703)) ([#5702](https://github.com/osquery/osquery/issues/5702))

Fix sqlite API usage errors ([#5551](https://github.com/osquery/osquery/pull/5551)) 

Fix issues reported by asan ([#5665](https://github.com/osquery/osquery/pull/5665))

Handle bad fds in `md_tables` ([#5553](https://github.com/osquery/osquery/pull/5533))

Fix lock resource leak in events/syslog ([#5552](https://github.com/osquery/osquery/pull/5552)) 

Fix memory leak in macOS `keychain_items` and `extended_attributes` tables ([#5550](https://github.com/osquery/osquery/pull/5550), [#5538](https://github.com/osquery/osquery/pull/5538))

Fix memory leak in `genLoggedInUsers` (Windows). Update `WTSFreeMemoryEx` to `WTSFreeMemory` ([#5642](https://github.com/osquery/osquery/pull/5642))

Fix potential null dereferences ([#5332](https://github.com/osquery/osquery/pull/5332))

Fix osquery exiting with wrong status (3824c2e6)

Add additional flag incompatibility check (85eb77a0)

Fix warning with constants initialisation in magic.cpp (2a624f2f)

Fix sign compare warning in file_compression.cpp (b93069b3)

Refactored `logical_drives` table on Windows to be more C++11 ([#5400](https://github.com/osquery/osquery/pull/5400))

Refactored core/windows/wmi to use smart pointers ([#5492](https://github.com/osquery/osquery/pull/5492))


### Bug Fixes

Fix: Config views now recreated on startup ([#5732](https://github.com/osquery/osquery/pull/5732))

Change MSI Service Error handling ([#5467](https://github.com/osquery/osquery/pull/5467))

Allow mounting SQLite DBs using WAL journaling with ATC ([#5525](https://github.com/osquery/osquery/issues/5225), [#5633](https://github.com/osquery/osquery/pull/5633))

Fix for mount table interacting with direct autofs. ([#5635](https://github.com/osquery/osquery/pull/5635)) 

Fix HTTP Host Header and port logic ([#5576](https://github.com/osquery/osquery/pull/5576))

windows/certificates: Fix bug in environment variable expansion ([#5697](https://github.com/osquery/osquery/pull/5697))

windows/certificates: Do not filter out system accounts ([#5696](https://github.com/osquery/osquery/pull/5696))

windows/certificates: Improve table's coverage of Personal certificates ([#5640](https://github.com/osquery/osquery/pull/5640))

windows/certificates: Fix enumeration bugs ([#5631](https://github.com/osquery/osquery/pull/5631))

tables: Add optimization back to macOS `users` and `groups` ([#5684](https://github.com/osquery/osquery/pull/5684))

Don't return a battery row, if there are no results ([#5650](https://github.com/osquery/osquery/pull/5650)) 

Fix several integer conversions in process_ops ([#5614](https://github.com/osquery/osquery/pull/5614))

Include weekends on the kernel_panics table ([#5298](https://github.com/osquery/osquery/pull/5298))

Fix `key_strength` bug for windows certificates table ([#5304](https://github.com/osquery/osquery/pull/5304))

Fix: `interface` column of `routes` table could be empty on Windows (bcf0ab8e)

Fix: `name` column of `programs` table could be empty on Windows (7bceba4b)

Fix `disable_watcher` flag (08dc11b7)

Fix: populate `path` column correctly in `firefox_addons` table ([#5462](https://github.com/osquery/osquery/pull/5462))

Fix numeric monitoring plugin not being registered ([#5484](https://github.com/osquery/osquery/pull/5484))

Fix wrong error code returned when querying the Windows registry ([%5621](https://github.com/osquery/osquery/pull/5621))

Fix windows/logical_drives boot partition detection ([#5477](https://github.com/osquery/osquery/pull/5477))

Replace sync calls by async ones ([#5606](https://github.com/osquery/osquery/pull/5606))

Fix rocksDB crash (a31d7582)

Fix bug in table column data validator (e3037331)

Fix random port problem (a32ed7c4)

Refactor battery table and return some information even if advanced information is missing (6a64e353)


### Table Changes


Added table `ibridge_info` on macOS (Notebooks only) ([#5707](https://github.com/osquery/osquery/pull/5707))

Added table `running_apps` on macOS ([#5216](https://github.com/osquery/osquery/pull/5216))

Added table `atom_packages` on macOS and Linux ([6d159d40](https://github.com/osquery/osquery/commit/6d159d40))

Remove EC2 tables on Windows where were unavailable) ([#5657](https://github.com/osquery/osquery/pull/5657))

Added column `win_timestamp` to `time` table on Windows ([3bbe6c51](https://github.com/osquery/osquery/commit/3bbe6c51))

Added column `is_hidded` to `users` and `groups` table on macOS ([#5368](https://github.com/osquery/osquery/pull/5368))

Added column `profile` to `chrome_extensions` table ([#5213](https://github.com/osquery/osquery/pull/5213))

Added column `epoch` to `rpm_packages` table on Linux ([#5248](https://github.com/osquery/osquery/pull/5248))

Added column `sid` to `logged_in_users` table on Windows ([#5454](https://github.com/osquery/osquery/pull/5454))
Added column `registry_hive` to `logged_in_users` table on Windows ([#5454](https://github.com/osquery/osquery/pull/5454))

Added column `sid` to `certificates` table on Windows ([#5631](https://github.com/osquery/osquery/pull/5631))

Added column `store_location` to `certificates` table on Windows ([#5631](https://github.com/osquery/osquery/pull/5631))

Added column `store` to `certificates` table on Windows ([#5631](https://github.com/osquery/osquery/pull/5631))

Added column `username` to `certificates` table on Windows ([#5631](https://github.com/osquery/osquery/pull/5631))

Added column `store_id` to `certificates` table on Windows ([#5631](https://github.com/osquery/osquery/pull/5631))

Added column `product_version`  to `file` table on Windows ([#5431](https://github.com/osquery/osquery/pull/5431))

Added column `source` to `sudoers` table on POSIX systems ([#5350](https://github.com/osquery/osquery/pull/5350))
