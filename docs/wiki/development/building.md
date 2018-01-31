## Dependencies

We include a `make deps` command to make it easier for developers to get started with the osquery project. `make deps` uses Homebrew for macOS and Linuxbrew for Linux. The following basic dependencies are need before running `make deps`:

- `sudo`
- `make` (that is, GNU make)
- `python`
- `ruby`
- `git`
- `bash`

> NOTICE: This will install or build various dependencies on the build host that are not required to "use" osquery, only build osquery binaries and packages.

For our build hosts (CentOS, Ubuntu 12, 14, 16, macOS 10.12, Windows 2016) we use a `sysprep` target to update the host and install these basic dependencies.

```sh
make sysprep
```

## Building on macOS

`make deps` will take care of installing the appropriate library dependencies, but it's recommended to take a look at the Makefile, just in case something conflicts with your environment.

The complete installation/build steps are as follows:

```sh
$ git clone https://github.com/facebook/osquery.git
$ cd osquery
$ # make sysprep
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

osquery supports almost all distributions of Linux.

For some distros, we supply vagrant infrastructure for creating native operating system packages. To create a package (e.g. a deb on Ubuntu or an rpm on CentOS), simply spin up a vagrant instance.

For example:

```sh
$ vagrant up ubuntu14
$ vagrant ssh ubuntu14
```

By default vagrant will allocate 2 virtual CPUs to the virtual machine instance. You can override this by setting `OSQUERY_BUILD_CPUS` environment variable before spinning up an instance. To allocate the maximum number of CPUs, `OSQUERY_BUILD_CPUS` can be set as:

```sh
OSQUERY_BUILD_CPUS=`nproc`             # for Linux
OSQUERY_BUILD_CPUS=`sysctl -n hw.ncpu` # for MacOS
```

Once you have logged into the vagrant box, run the following to create a package:

```sh
$ cd /vagrant
$ make sysprep
$ make deps
$ make
$ make test
```

The binaries are built to a distro-specific folder within *build* and symlinked in:

```sh
$ ls -la ./build/linux/osquery/
```

## Submitting Pull Requests

Once you have made changes you'll want to submit them to Github as a Pull Request. There are tons of wonderful guides and documentation around Pull Requests, and that is just out of scope for this wiki-- but consider the following workflow:

```
$ git checkout -b new_feature1
$ # write some code!
$ make -j 4
$ git commit -m "New Feature: do something wonderful"
$ git push
```

This assumes your remote `origin` is your osquery fork, and that you receive updates from an `upstream`. It is also common to use `origin` as `facebook/osquery` then add your fork as a target named after your Github username.

In that case the final push becomes `git push USERNAME`.

### Testing changes

Our Jenkins CI will test your changes in three steps.

1. A code audit is run using `make audit`.
2. The code is rebuilt, built again for release, then a package is generated using `./tools/build.sh` on various Linux and macOS versions.
3. The same step is run on Windows 10.

The audit step attempts to build the documentation, run code formatting checks, and a brief static code analysis. The formatting check is performed with `clang-format` (installed with `make deps` to your osquery dependencies directory). Your changes are compared against the local `master` branch. Within the build host this is always the TIP of `facebook/osquery`, but locally the branch may be behind.

To speed up the format auditing process please configure your code editor to run `clang-format` on files changed. Or periodically during your development run `make format_master`. Running `make check` is also helpful, but it will use `cppcheck` which is not installed by default.

## Dependencies and build internals

The `make deps` command is fairly intense and serves two purposes: (1) to communicate a standard set of environment setup instructions for our build and test nodes, (2) to provide an environment for reproducing errors. The are wonderful auxiliary benefits such as controlling the compiler and compile flags for almost all of our dependencies, controlling security-related features for dependencies, allowing a "mostly" universal build for Linux that makes deployment simple. To read more about the motivation and FAQ for our dependencies environment see the [Github Reference #2253](https://github.com/facebook/osquery/issues/2253).

When using `make deps` the environment the resultant binaries will have a minimum set of requirements to run:

- `glibc` version 2.13
- `libgcc_s`
- `libz`

All other dependencies are built, compiled, and linked statically. This makes for a rather large set of output binaries (15M on Linux and 9M on macOS) but the trade-off for deployment simplicity is very worthwhile.

Under the hood the `make deps` script is calling `./tools/provision.sh`, which performs the simplified set of steps:

- Create a "runtime" directory or dependency home: `/usr/local/osquery`.
- Clone a pinned version of Homebrew or Linuxbrew into that home.
- Install a local Tap using `./tools/provision/formulas` into that home.
- Run optional distro-specific setup scripts from `./tools/provision/DISTRO.sh`.
- Install a list of packages from the local Tap defined in `./tools/provision.sh`.

We use a minimum set of packages from Homebrew and Linuxbrew, mostly just tools. The remaining tools and C/C++ library dependencies as well as C and C++ runtimes are built from source. If we need to change compile options or variables we can bump these formula's bottle revisions.

### Adding or changing dependencies

If you need to bump a dependency version, change the way it is built, or add a new dependency-- use the formulas in `./tools/provision/formula/`. Let's consider a simple example:

```
require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libaudit < AbstractOsqueryFormula
  desc "Linux auditing framework"
  url "https://github.com/Distrotech/libaudit/archive/audit-2.4.2.tar.gz"
  sha256 "63020c88b0f37a93438894e67e63ccede23d658277ecc6afb9d40e4043147d3f"

  def install
    system "./autogen.sh"
    system "./configure", "--prefix=#{prefix}"
    cd "lib" do
      system "make"
      system "make", "install"
    end
  end
end
```

This looks A LOT like normal *brew formulas. For a new dependency do not add a `bottle` section. For help with writing formulas see [Homebrew's Formula Cookbook](https://github.com/Homebrew/brew/blob/master/share/doc/homebrew/Formula-Cookbook.md). Note that we use an Abstract to control the environment variables and control relocation on Linux.

If you want to make build changes see the Cookbook for `revision` edits. Note that committing new or edited formulas will invalidate package caches this will cause the package to be built from source on the test/build hosts.

**If this is a new dependency** then you need to add a line to `./tools/provision.sh` for Linux and or macOS at the order/time it should be installed.

When a dependency is updated by a maintainer or contributor the flow should follow:
* Update the target formula in `./tools/provision/formula/`.
* Run `make deps` and the dependency change should cause a rebuild from source.
* Build and run the osquery tests, and submit the change in a pull request.

After the change is merged, a maintainer can provide a bottle/binary version:
* Run `./tools/provision.sh uninstall TARGET` to remove the from-source build.
* Run `make build_deps` to build a bottle version from source.
* Run `./tools/provision.sh bottle TARGET` to generate the bottle.
* Update the formula again with the SHA256 printed to stdout.
* Upload the `/usr/local/osquery/TARGET-VERSION.tar.gz` to the S3 `bottles` folder.
* Create a pull request with the updated SHA256.

## AWS EC2 Backed Vagrant Targets

The osquery vagrant infrastructure supports leveraging AWS EC2 to run virtual machines.
This capability is provided by the [vagrant-aws](https://github.com/mitchellh/vagrant-aws) plugin, which is installed as follows:

```sh
$ vagrant plugin install vagrant-aws
```

Next, add a vagrant dummy box for AWS:

```sh
$ vagrant box add andytson/aws-dummy
```

Before launching an AWS-backed virtual machine, a few environment variables must be set:

```sh
# Required. Credentials for AWS API. vagrant-aws will error if these are unset.
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
# Name of AWS keypair for launching and accessing the EC2 instance.
export AWS_KEYPAIR_NAME=my-osquery-vagrant-security-group
export AWS_SSH_PRIVATE_KEY_PATH=/path/to/keypair.pem
# Name of AWS security group that allows TCP/22 from vagrant host.
# If using a non-default VPC use the security group ID instead.
export AWS_SECURITY_GROUP=my-osquery-vagrant-security-group
# Set this to the AWS region, "us-east-1" (default) or "us-west-1".
export AWS_DEFAULT_REGION=...
# Set this to the AWS instance type. If unset, m3.medium is used.
export AWS_INSTANCE_TYPE=m3.large
# (Optional) Set this to the VPC subnet ID.
# (Optional) Make sure your subnet assigns public IPs and there is a route.
export AWS_SUBNET_ID=...
```

Spin up a VM in EC2 and SSH in (remember to suspect/destroy when finished):

```sh
$ vagrant up aws-amazon2015.03 --provider=aws
$ vagrant ssh aws-amazon2015.03
```

## Debug Builds, formatting, and more

To generate a non-optimized debug build use `make debug`.

CMake regenerates build information every time `make [all]` is run. To avoid the "configure" and project setup use `make build`.

make building and testing macros:

```sh
make # Default optimized configure/build
make test # Test the default build
make debug # Configure and build non-optimized with debuginfo
make test_debug # Test the debug build
make build # Skip the CMake project configure (compile only)
make debug_build # Same as build, but applied to the debug target
make test_debug_build # Take a guess ;)
make clean # Clean the CMake project configuration
make distclean # Clean all cached information and build dependencies
make deps # Install the osquery dependency environment into /usr/local/osquery
make depsclean # Remove the dependency environment
make docs # Build the Doxygen and mkdocs wiki
```

There are several additional code testing and formatting macros:

```sh
make format_master # Format everything changed from the local master branch
make format_all # Not recommended but formats the entire code base
make format # Apply clang-format using osquery's format spec*
make analyze # Run clean first, then rebuild with the LLVM static analyzer
make sanitize # Run clean first, then rebuild with sanitations
make fuzz # Run basic fuzz tests, as defined in each table spec
make audit # The clang-format and other PR-blocking checks
make check # Run cpp-check and output style/performance/error warnings
```

Generating the osquery SDK or sync:

```sh
make sdk # Build only the osquery SDK (libosquery.a)
make sync # Create a tarball for building the SDK externally
```

Finally, subtle changes to the build are mostly controlled through environment
variables. When making these changes it is best to removed your build cache
by removing the `./build/` or `./build/{platform}/` directory.

```sh
OSQUERY_BUILD_LINK_SHARED=True # Prefer linking against shared libraries
OSQUERY_BUILD_SHARED=True # Build and link a shared libosquery.
OSQUERY_BUILD_DEPS=True # Install dependencies from source when using make deps
OSQUERY_BUILD_BOTTLES=True # Create bottles from installed dependencies
OSQUERY_BUILD_VERSION=9.9.9 # Set a wacky version string
OSQUERY_PLATFORM=custom_linux;1.0 # Set a wacky platform/distro name
OSQUERY_OSQUERY_DEPS=/usr/local/osquery # Set alternative dependency path
OSQUERY_NOSUDO=True # If sudo is not available to user building osquery
SDK_VERSION=9.9.9 # Set a wacky SDK-version string.
OSX_VERSION_MIN=10.11 # Override the native minimum macOS version ABI
OSQUERY_DEPS=/path/to/dependencies # Use a custom dependency environment
FAST=True # Build and link as quick as possible.
SANITIZE_THREAD=True # Add -fsanitize=thread when using "make sanitize"
SANITIZE_UNDEFINED=True # Add -fsanitize=undefined when using "make sanitize"
OPTIMIZED=True # Enable specific CPU optimizations (not recommended)
SQLITE_DEBUG=True # Enable SQLite query debugging (very verbose!)
```

There are various features that can be disabled with a customized build. These are also controlled by environment variables to be as cross-platform as possible and take the form: `SKIP_*`. These are converted into CMake variables within the root `CMakeLists.txt`.

```sh
SKIP_AWS=True # Skip the various AWS integrations
SKIP_TSK=True # Skip SleuthKit integrations
SKIP_LLDPD=True # Skip LLDP tables
SKIP_YARA=True # Skip Yara integrations, both events and the virtual tables
SKIP_KAFKA=True # Skip support for Kafka logger plugins
SKIP_CARVER=True # Skip support for file carving
SKIP_KERNEL=True # Enabled by default, set to 'False' to enable
SKIP_TESTS=True # Skip unit test building (very very not recommended!)
SKIP_INTEGRATION_TESTS=True # Skip python tests when using "make test"
SKIP_BENCHMARKS=True # Build unit tests but skip building benchmark targets
SKIP_TABLES=True # Build platform without any table implementations or specs
SKIP_DISTRO_MAIN=False # Run the sysprep update/install within make deps
```

## Custom Packages

Building osquery on macOS or Linux requires a significant number of dependencies, which are not needed when deploying. It does not make sense to install osquery on your build hosts. See the [Custom Packages](../installation/custom-packages.md) guide for generating PKGs, debs or RPMs.

Debug and from-source package building is not recommended but supported. You may generate several packages including devel, debuginfo, and additional sets of tools:

```sh
make package # Generate an osquery package for the build target
make packages # Generate optional/additional packages
```

These targets set the environment variable `PACKAGE=1` and the CMake variable `OSQUERY_BUILD_RELEASE` that enables allows build and CMake logic to make compile and linking decisions. This may enable additional compile defines or remove sources from targets.

The osquery package build hosts run a series of additional unit and integration tests. This involves building targets with debug routines, testing, building the same targets ready for packaging, testing, and running a final set of "sanity" and deployment tests.

To mimic and follow the same build/release testing workflow use:

```
export RUN_BUILD_DEPS=1
export RUN_RELEASE_TESTS=1
./tools/build.sh
```

Pay attention to the environment variable `RUN_RELEASE_TESTS=1`, which enables the deployment sanity tests. If you are building an optimized or distribution package manager target this will most likely fail. The `RUN_BUILD_DEPS` variable tells the build to begin with a `make deps`.

## Notes and FAQ

When trying to make, if you encounter:
```
Requested dependencies may have changed, run: make deps
```

You must run `make deps` to make sure you are pulling in the most-recent dependency assumptions. This error typically means a new virtual table has been added that includes new third-party development libraries.

`make deps` will take care of installing everything you need to compile osquery. However, to properly develop and contribute code, you'll need to install some additional programs. If you write C++ often, you likely already have these programs installed. We don't bundle these tools with osquery because many programmers are quite fond of their personal installations of LLVM utilities, debuggers, etc.

- clang-format: we use clang-format to format all code in osquery. After staging your commit changes, run `make format` (requires clang-format).
- valgrind: performance is a top priority for osquery, so all code should be thoroughly tested with valgrind or instruments. After building your code use `./tools/analysis/profile.py --leaks` to run all queries and test for memory leaks.

## Build Performance

Generating a virtual table should NOT impact system performance. This is easier said than done as some tables may _seem_ inherently latent such as `SELECT * from suid_bin;` if your expectation is a complete filesystem traversal looking for binaries with suid permissions. Please read the osquery features and guide on [performance safety](../deployment/performance-safety.md).

Some quick features include:

* Performance regression and leak detection CI guards.
* Blacklisting performance-impacting virtual tables.
* Scheduled query optimization and profiling.
* Query implementation isolation options.
