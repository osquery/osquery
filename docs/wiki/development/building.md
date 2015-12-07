## Dependencies

We include a `make deps` command to make it easier for developers to get started with the osquery project. `make deps` uses Homebrew for OS X and traditional package managers for various distributions of Linux. Please have sudo installed before running `make deps`.

WARNING: This will install or build various dependencies on the build host that are not required to "use" osquery, only build osquery binaries and packages.

 If you're trying to run our automatic tool on a machine that is extremely customized and configured, `make deps` may try to install software that conflicts with software you have installed. If this happens, please create an issue and/or submit a pull request with a fix. We'd like to support as many operating systems as possible.

## Building on OS X

To build osquery on OS X, you need `pip` and `brew` installed. `make deps` will take care of installing the appropriate library dependencies, but it's recommended to take take a look at the Makefile, just in case
something conflicts with your environment.

Anything that does not have a Homebrew package is built from source from _https://github.com/osquery/third-party_, which is a git submodule of this repository and is set up by `make deps`.

The complete installation/build steps are as follows:

```sh
$ git clone https://github.com/facebook/osquery.git
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

By default vagrant will allocate 2 virtual CPUs to the virtual machine instance. You can override this by setting `OSQUERY_BUILD_CPUS` environment variable before spinning up an instance. To allocate the maximum number of CPUs, `OSQUERY_BUILD_CPUS` can be set as:

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
```

There are several additional code testing and formatting macros:

```sh
make format # Apply clang-format using osquery's format spec*
make format-all # Not recommended but formats the entire code base
make analyze # Run clean first, then rebuild with the LLVM static analyzer
make sanitize # Run clean first, then rebuild with sanitations
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
OSQUERY_PLATFORM=custom_linux;1.0 # Set a wacky platform/distro name
OSQUERY_BUILD_VERSION=9.9.9 # Set a wacky version string
BUILD_LINK_SHARED=True # Set CMake library discovery to prefer shared libraries
SDK_VERSION=9.9.9 # Set a wacky SDK-version string
SANITIZE_THREAD=True # Add -fsanitize=thread when using "make sanitize"
OPTIMIZED=True # Disable generic CPU optimizations
SKIP_TESTS=True # Skip unit test building (very very not recommended!)
SKIP_BENCHMARKS=True # Build unit tests but skip building benchmark targets
SKIP_TABLES=True # Build platform without any table implementations or specs
OSX_VERSION_MIN=10.11 # Override the native minimum OS X version ABI
```

## Custom Packages

Building osquery on OS X or Linux requires a significant number of dependencies, which are not needed when deploying. It does not make sense to install osquery on your build hosts. See the [Custom Packages](../installation/custom-packages.md) guide for generating pkgs, debs or rpms.

Debug and from-source package building is not recommended but supported. You may generate several packages including devel, debuginfo, and additional sets of tools:

```sh
make package # Generate an osquery package for the build target
make packages # Generate optional/additional packages
```

These targets set the environment variable `PACKAGE=1` and the CMake variable `OSQUERY_BUILD_RELEASE` that enables allows build and CMake logic to make compile and linking decisions. This may enable additional compile defines or remove sources from targets.

The osquery package build hosts run a series of additional unit and integration tests. This involves building targets with debug routines, testing, building the same targets ready for packaging, testing, and running a final set of "sanity" and deployment tests.

To mimic and follow the same build/release testing workflow use:

```
./tools/build.sh
```

Pay attention to the environment variable `RUN_RELEASE_TESTS=1`, which enables the deployment sanity tests. If you are building an optimized or distribution package manager target this will most likely fail.

## Notes and FAQ


When trying to make, if you encounter:

```
Requested dependencies may have changed, run: make deps
```

You must run `make deps` to make sure you are pulling in the most-recent dependency assumptions. This error typically means a new virtual table has been added that includes new third-party development libraries.

`make deps` will take care of installing everything you need to compile osquery. However, to properly develop and contribute code, you'll need to install some additional programs. If you write C++ often, you likely already have these programs installed. We don't bundle these tools with osquery because many programmers are quite fond of their personal installations of LLVM utilities, debuggers, etc.

- clang-format: we use clang-format to format all code in osquery. After staging your commit changes, run `make format` (requires clang-format).
- valgrind: performance is a top priority for osquery, so all code should be thoroughly tested with valgrind or instruments. After building your code use `./tools/profile.py --leaks` to run all queries and test for memory leaks.

## Build Performance

Generating a virtual table should NOT impact system performance. This is easier said than done as some tables may _seem_ inherently latent such as `SELECT * from suid_bin;` if your expectation is a complete filesystem traversal looking for binaries with suid permissions. Please read the osquery features and guide on [performance safety](../deployment/performance-safety.md).

Some quick features include:

* Performance regression and leak detection CI guards.
* Blacklisting performance-impacting virtual tables.
* Scheduled query optimization and profiling.
* Query implementation isolation options.
