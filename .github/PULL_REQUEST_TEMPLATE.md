<!-- Thank you for contributing to osquery! -->

To submit a PR please make sure to follow the next steps:

- [ ] Read the `CONTRIBUTING.md` guide at the root of the repo.
- [ ] Ensure the code is formatted building the `format_check` target.  
      If it is not, then move the committed files to the git staging area,
      build the `format` target to format them, and then re-commit.
      [More information is available on the wiki](https://osquery.readthedocs.io/en/latest/development/building/#formatting-the-code).
- [ ] Ensure your PR contains a single logical change.
- [ ] Ensure your PR contains tests for the changes you're submitting.
- [ ] Describe your changes with as much detail as you can.
- [ ] Link any issues this PR is related to.
- [ ] Remove the text above.

<!--

The PR will be reviewed by an osquery committer.
Here are some common things we look for:

- Common utilities within `./osquery/utils` are used where appropriate (avoid reinventions).
- Modern C++ structures and patterns are used whenever possible.
- No memory or file descriptor leaks, please check all early-return and destructors.
- No explicit casting, such as `return (int)my_var`, instead use `static_cast`.
- The minimal amount of includes are used, only include what you use.
- Comments for methods, structures, and classes follow our common patterns.
- `Status` and `LOG(N)` messages do not use punctuation or contractions.
- The code mostly looks and feels similar to the existing codebase.

-->
