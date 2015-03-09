For documentation on contributing to osquery, please read the [CONTRIBUTING.md](https://github.com/facebook/osquery/blob/master/CONTRIBUTING.md) file.

## Using `clang-format`

C++ can be very difficult to read, maintain and write if it's not written cleanly. Following uniform patterns throughout the entire codebase improves the entire codebase. With that being said, the last thing that you want to think about when you're trying to iterate quickly is how many of your lines are greater than 80 characters long. For this reason, osquery uses `clang-format` to automatically format code. **After you've written some code, stage your modified files, then execute `make format` from the root of the repository.** This automatically runs `clang-format` on all staged C/C++/Objective-C source code.

## Format style

The format style used by osquery is defined by the configurations of osquery's [.clang-format](https://github.com/facebook/osquery/blob/master/.clang-format) file. When osquery's ".clang-format" file doesn't specify a preference for a configurable clang-format decision, assume that `clang-format`'s default behavior is correct.

## Style guide

If you would really like a style guide to follow or refer to, please use the [LLVM Coding Standards](http://llvm.org/docs/CodingStandards.html). 

Keep in mind, osquery's style configurations are slightly different than vanilla LLVM coding standards, so be sure to still run `make format` before submitting any code.