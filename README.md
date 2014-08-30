osquery
=======

## Building on OS X

To build osquery on OS X, all you need installed is `pip` and `brew`.
`make deps` will take care of installing the appropriate library
dependencies, but I recommend taking a look at the Makefile, just in case
you see something that might conflict with your personal setup.

Anything that doesn't have a homebrew package is built from source from
https://github.com/osquery/third-party, which is a git submodule of this
repository which is set up by `make deps`.

The complete installation/build steps are as follows:

```
git clone git@github.com:facebook/osquery.git
cd osquery
make deps
make
```

Once the project is built, try running the project's unit tests:

```
make runtests
```

## Table Development

### Top easy virtual tables

- [Crontab virtual table](https://github.com/facebook/osquery/issues/19)
- [Networking settings virtual table](https://github.com/facebook/osquery/issues/10)
- [Full Disk Encryption Virtual Tables](https://github.com/facebook/osquery/issues/15)

### High impact virtual tables
- [Installed browser plugins virtual table](https://github.com/facebook/osquery/issues/24)
- [System-trusted root certificated virtual table](https://github.com/facebook/osquery/issues/8)
- [Startup items virtual table](https://github.com/facebook/osquery/issues/6)


### Testing your table for memory leaks

Use valgrind to test your table for memory leaks before you commit it. The osqueryd daemon is a very long running processes, so avoiding memory leaks is critical. The "run" tool is useful for testing a specific query. From the root of the osquery repository, run the following (substitute your table name in the query):

```
valgrind --tool=memcheck --leak-check=yes --suppressions=osquery.supp ./build/tools/run --query="select * from time;"
```
