# Adding new options and arguments to osquery

How do I add a new command-line flag/option/argument to osquery? Well, first familiarize yourself with [gflags](https://github.com/gflags/gflags), then take note of the wrapper below.

[osquery/core/flags.h](https://github.com/osquery/osquery/blob/master/osquery/core/flags.h) contains a single wrapper for `gflags::DEFINE_` type style macros. osquery includes a simple wrapper for defining arguments/options/flags for the osqueryd daemon and shell.

Instead of writing the normal gflags macro for defining a new option:

```cpp
#include <gflags/gflags.h>
// This is the WRONG way to define a flag in osquery.
DEFINE_bool(you_are_awesome, true, "Ground truth for awesome.");  // DON'T DO THIS!
```

Use the following wrapper:

```cpp
#include <osquery/core/flags.h>

FLAG(bool, you_are_awesome, true, "Ground truth for awesome.");
```

If you are declaring a flag before defining it, no change is needed. Use `DECLARE_bool(you_are_awesome);` like normal. There is no change for accessing the flag either. Use `if (FLAG_you_are_awesome)` like normal.

This will allow osquery callers to show pretty displays when `-h, --help` is used.

> NOTICE: restrict your default values to code literals. It does not help to abstract the default variable into a constant then use it singularly in the macro.
