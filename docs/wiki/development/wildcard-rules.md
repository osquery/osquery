osquery has a simplified wildcarding system for matching operating system directories and files.

* `%`: Match all
* `%%`: Match all recursively
* `%XX`: Match all ending in "XX"
* `XX%`: Match all starting with "XX"

**Examples**

* `/bin/%`: Resolves a vector of every file in "/bin"
* `/bin/%%`: Match all files in bin and all files in any sub directory(n deep, to a limit)
* `/bin/%sh`: Match all files in "/bin" ending with "sh" ("/bin/bash", "/bin/sh", "/bin/zsh", ...)
* `/bin/ba%`: Match all files in "/bin" starting with "ba". ("/bin/bash")

**Matching Gotchas**

`%XX%` and `XX%XX`: are undefined and will not resolve wildcards in the expected way. This may be implemented in future but there are no plans.
