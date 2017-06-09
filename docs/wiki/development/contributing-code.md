For documentation on contributing to osquery, please read the [CONTRIBUTING.md](https://github.com/facebook/osquery/blob/master/CONTRIBUTING.md) file.

## Using `clang-format`

C++ can be very difficult to read, maintain and write if it's not written cleanly. Following uniform patterns throughout the entire codebase improves the entire codebase. With that being said, the last thing that you want to think about when you're trying to iterate quickly is how many of your lines are greater than 80 characters long. For this reason, osquery uses `clang-format` to automatically format code. **After you've written some code, stage your modified files, then execute `make format_master` from the root of the repository.** This automatically runs `clang-format` on all staged C/C++/Objective-C source code.

## Format style

The format style used by osquery is defined by the configurations of osquery's [.clang-format](https://github.com/facebook/osquery/blob/master/.clang-format) file. When osquery's ".clang-format" file doesn't specify a preference for a configurable clang-format decision, assume that `clang-format`'s default behavior is correct.

## Style guide

If you would really like a style guide to follow or refer to, please use the [LLVM Coding Standards](http://llvm.org/docs/CodingStandards.html).

Keep in mind, osquery's style configurations are slightly different than vanilla LLVM coding standards, so be sure to still run `make format_master` before submitting any code.

## Linting

osquery has some basic linting for documentation that gets rendered on the [osquery tables](https://osquery.io/docs/tables/) page. Breaking these linting rules will cause table generation to fail and all builds will break.

**Active Linting Rules**

- Table descriptions must end in a period: Try to make table descriptions full sentences.

**Upcoming Linting Rules**

- Table specs must have examples: Give one or two examples of how your table could be used. Generally one simple and a complex one but if your table just needs a `SELECT * FROM [table]`, that's also fine.
