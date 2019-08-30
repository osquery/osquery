<a name="4.0.1"></a>
## [4.0.0](https://github.com/osquery/osquery/compare/3.3.2...4.0.0) (2019-06-28)




### New Features

Audit — `process_events` Implement support for fork/vfork/clone/execveat ([#5701](https://github.com/osquery/osquery/pull/5701))

New SQLite function `regex_match` to match across columns ([#5444](https://github.com/osquery/osquery/pull/5444))

macOS query pack: detect SearchAwesome malware ([#5713](https://github.com/osquery/osquery/pull/5713))

macOS query pack: detect when a process is tapping keyboard event ([#5345](https://github.com/osquery/osquery/pull/5345))


### Build

Add CMake support ([#5604](https://github.com/osquery/osquery/pull/5604), [#5627](https://github.com/osquery/osquery/pull/5627), [#5630](https://github.com/osquery/osquery/pull/5630))

Add Azure Pipelines support for CI/CD ([#5604](https://github.com/osquery/osquery/pull/5604), [#5632](https://github.com/osquery/osquery/pull/5632), [#5626](https://github.com/osquery/osquery/pull/5626), [#5613](https://github.com/osquery/osquery/pull/5613), [#5607](https://github.com/osquery/osquery/pull/5607), [#5673](https://github.com/osquery/osquery/pull/5673), [#5610](https://github.com/osquery/osquery/pull/5610))

Fix buck builds ([#5647](https://github.com/osquery/osquery/pull/5647), [#5623](https://github.com/osquery/osquery/pull/5623))

Use `urllib2` to automatically handle HTTP 301/302 redirections ([#5612](https://github.com/osquery/osquery/pull/5612))

### Harderning

sqlite: Remove FTS features from sqlite ([#5703](https://github.com/osquery/osquery/pull/5703)) ([#5702](https://github.com/osquery/osquery/issues/5702))

Fix sqlite API usage errors ([#5551](https://github.com/osquery/osquery/pull/5551)) 

Fix issues reported by asan ([#5665](https://github.com/osquery/osquery/pull/5665))

Handle bad fds in `md_tables` ([#5553](https://github.com/osquery/osquery/pull/5533))

Fix lock resource leak in events/syslog ([#5552](https://github.com/osquery/osquery/pull/5552)) 

Fix memory leak in macOS `keychain_items` and `extended_attributes` tables ([#5550](https://github.com/osquery/osquery/pull/5550), [#5538](https://github.com/osquery/osquery/pull/5538))

Fix memory leak in `genLoggedInUsers` (Windows). Update `WTSFreeMemoryEx` to `WTSFreeMemory` ([#5642](https://github.com/osquery/osquery/pull/5642))

Fix potential null dereferences ([#5332](https://github.com/osquery/osquery/pull/5332))


### Bug Fixes

Change MSI Service Error handling ([#5467](https://github.com/osquery/osquery/pull/5467))


Allow mounting SQLite DBs using WAL journaling with ATC ([#5525](https://github.com/osquery/osquery/issues/5225), [#5633](https://github.com/osquery/osquery/pull/5633))

Fix for mount table interacting with direct autofs. ([#5635](https://github.com/osquery/osquery/pull/5635)) 

Fix HTTP Host Header and port logic ([#5576](https://github.com/osquery/osquery/pull/5576))

windows/certificates: Fix bug in environment variable expansion ([#5697](https://github.com/osquery/osquery/pull/5697))

windows/certificates: Do not filter out system accounts ([#5696](https://github.com/osquery/osquery/pull/5696))

windows/certificates: Improve table's coverage of Personal certificates ([#5640](https://github.com/osquery/osquery/pull/5640))

windows/certificates: Fix enumeration bugs, add columns ([#5631](https://github.com/osquery/osquery/pull/5631)) **MOVE to Table Changes**


tables: Add optimization back to macOS `users` and `groups` ([#5684](https://github.com/osquery/osquery/pull/5684))

Don't return a battery row, if there are no results ([#5650](https://github.com/osquery/osquery/pull/5650)) 

Fix several integer conversions in process_ops ([#5614](https://github.com/osquery/osquery/pull/5614))

Include weekends on the kernel_panics table ([#5298](https://github.com/osquery/osquery/pull/5298))

Fix `key_strength` bug for windows certificates table ([#5304](https://github.com/osquery/osquery/pull/5304))


### Table Changes

* d9fdc5b8 - tables: implement ibridge table to report on T1/T2 chip for mac notebooks  ([#5707](https://github.com/osquery/osquery/pull/5707))
* d7c7a1de - Remove cloud tables from windows (#5657) (Remove EC2 tables from windows where were unavailable)
* 507638dd - chrome_extensions: Add the profile name to the table (#5213) 
* 898ed37d - Table for OSX Running and Active Applications (https://github.com/osquery/osquery/pull/5216)
* 3bbe6c51 - win_timestamp column of time table is windows specific 
* bcf0ab8e - interface column of routes table could be empty on windows 
* 7bceba4b - Name column in programs table could be emtpy on windows
* 6fe7b4cb - Epoch in rpm_packages table (#5248) 
* fe70a514 - windows/logged_in_users: Add sid, hive columns (#5454) 
* 139aaef0 - windows/logical_drives: Refactor (#5400) 
* 5edb4c5b - Add Windows product version information to file table (#5431) 


