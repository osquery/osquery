<!-- Thank you for contributing to osquery! -->

To submit a PR please make sure to follow the next steps:

- [ ] Read the `CONTRIBUTING.md` guide on the root of the repo.
- [ ] Ensure your PR contains a single logical change.
- [ ] Ensure your PR contains tests for the changes you're submitting.
- [ ] Describe your changes with as much detail as you can.
- [ ] Link any issues this PR is related to.
- [ ] Remove the text above.

<!--

The PR will be reviewed by an osquery committer.
Here are some common things we look for:

- The code is formatted correctly, considering using `make format_check`.
- Common utilities within `./osquery/utils` are used where appropriate (avoid reinventions).
- Modern C++11 structures and patterns are used where appropriate.
- No memory or file descriptor leaks, please check all early-return and destructors.
- No explicit casting, such as `return (int)my_var`, instead use `static_cast`.
- The minimal ammount of includes are used, only include what you use.
- Comments for methods, structures, and classes follow our common patterns.
- `Status` and `LOG(N)` messages do not use punctuation or contractions.
- Support for both CMake and BUCK (we are happy to help).
- The code mostly looks and feels similar to the existing codebase.

-->
