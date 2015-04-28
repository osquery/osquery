## Dependencies

We include a `make deps` command to make it easier for developers to get started with the osquery project. `make deps` uses homebrew for OS X and traditional package managers for various distributions of Linux.

WARNING: This will install or build various dependencies on the build host that are not required to "use" osquery, only build osquery binaries and packages.

 If you're trying to run our automatic tool on a machine that is extremely customized and configured, `make deps` may try to install software that conflicts with software you have installed. If this happens, please create an issue and/or submit a pull request with a fix. We'd like to support as many operating systems as possible.

## Building on OS X

To build osquery on OS X, you need `pip` and `brew` installed. `make deps` will take care of installing the appropriate library dependencies, but it's recommended to take take a look at the Makefile, just in case
something conflicts with your environment.

Anything that does not have a homebrew package is built from source from *https://github.com/osquery/third-party*, which is a git submodule of this repository and is set up by `make deps`.

The complete installation/build steps are as follows:

```sh
$ git clone git@github.com:facebook/osquery.git
$ cd osquery
$ make deps
$ make
```

Once the project is built, try running the project's unit tests:

```sh
$ make test
```

And the binaries are built in:

```sh
$ ls -la ./build/darwin/osquery/
```

## Building on Linux

osquery supports several distributions of Linux.

For each supported distro, we supply vagrant infrastructure for creating native operating system packages. To create a package (e.g. a deb on Ubuntu or an rpm on CentOS), simply spin up a vagrant instance.

For example:

```sh
$ vagrant up ubuntu14
$ vagrant ssh ubuntu14
```

By default vagrant will allocate 2 virtual CPUs to the virtual machine instance. You can override this by setting `OSQUERY_BUILD_CPUS` environment variable before spinning up an instance. To allocate the maximum number of CPUs `OSQUERY_BUILD_CPUS` can be set as:

```sh
OSQUERY_BUILD_CPUS=`nproc`             # for Linux
OSQUERY_BUILD_CPUS=`sysctl -n hw.ncpu` # for OS X
```

Once you have logged into the vagrant box, run the following to create a package:

```sh
$ cd /vagrant
$ make deps
$ make
$ make test
```

The binaries are built to a distro-specific folder within *build* and symlinked in:

```sh
$ ls -la ./build/linux/osquery/
```

## Custom Packages

Building osquery on OS X or Linux requires a significant number of dependencies, which
are not needed when deploying. It does not make sense to install osquery on
your build hosts. See the [Custom Packages](../installation/custom-packages) guide
for generating pkgs, debs or rpms.

## Notes and FAQ


When trying to make, if you encounter:

```
Requested dependencies may have changed, run: make deps
```

You must run `make deps` to make sure you are pulling in the most-recent dependency assumptions. This error typically means a new virtual table has been added that includes new third-party development libraries.

`make deps` will take care of installing everything you need to compile osquery. However, to properly develop and contribute code, you'll need to install some additional programs. If you write C++ often, you likely already have these programs installed. We don't bundle these tools with osquery because many programmers are quite fond of their personal installations of LLVM utilities, debuggers, etc.

- clang-format: we use clang-format to format all code in osquery. After staging your commit changes, run `make format`. (requires clang-format)
- valgrind: performance is a top priority for osquery, so all code should be thoroughly tested with valgrind or instruments. After building your code use `./tools/profile --leaks` to run all queries and test for memory leaks.

## Build Performance

Generating a virtual table should NOT impact system performance. This is easier said than done as some tables may _seem_ inherently latent such as `SELECT * from suid_bin;` if your expectation is a complete filesystem traversal looking for binaries with suid permissions. Please read the osquery features and guide on [performance safety](../deployment/performance-safety.md).

Some quick features include:

* Performance regression and leak detection CI guards.
* Blacklisting performance-impacting virtual tables.
* Scheduled query optimization and profilling.
* Query implementation isolation options.
