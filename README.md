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
