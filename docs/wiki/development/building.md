# Building osquery from source

osquery supports many flavors of Linux, macOS, and Windows.

While osquery runs on a large number of operating systems, we only provide build instructions for a select few.

The supported compilers are: the osquery toolchain (LLVM/Clang 9.0.1) on Linux, MSVC v142 on Windows, and AppleClang from Xcode Command Line Tools 10.2.1.

## Prerequisites

Git (>= 2.14.0), CMake (>= 3.17.5), Python 3 are required to build. The rest of the dependencies are downloaded by CMake.

The default build type is `RelWithDebInfo` (optimizations active + debug symbols) and can be changed in the CMake configure phase by setting the `CMAKE_BUILD_TYPE` flag to `Release` or `Debug`.

The build type is chosen when building on Windows, through the `--config` option, not during the configure phase.

Note: the recommended system memory for building osquery is at least 8GB, or Clang may crash during the compilation of third-party dependencies.

## Linux (Ubuntu 18)

The initial directory is assumed to be `/home/<user>`.

```bash
# Install the prerequisites
sudo apt install --no-install-recommends git python3 bison flex make

# Optional: install python tests prerequisites
sudo apt install --no-install-recommends python3-pip python3-setuptools python3-psutil python3-six python3-wheel
pip3 install timeout_decorator thrift==0.11.0 osquery pexpect==3.3

# Optional: install RPM packaging prerequisites
sudo apt install --no-install-recommends rpm binutils

# Download and install the osquery toolchain
wget https://github.com/osquery/osquery-toolchain/releases/download/1.1.0/osquery-toolchain-1.1.0-x86_64.tar.xz
sudo tar xvf osquery-toolchain-1.1.0-x86_64.tar.xz -C /usr/local

# Download and install a newer CMake
wget https://cmake.org/files/v3.17/cmake-3.17.5-Linux-x86_64.tar.gz
sudo tar xvf cmake-3.17.5-Linux-x86_64.tar.gz -C /usr/local --strip 1
# Verify that `/usr/local/bin` is in the `PATH` and comes before `/usr/bin`

# Download source
git clone https://github.com/osquery/osquery
cd osquery

# Build osquery
mkdir build; cd build
cmake -DOSQUERY_TOOLCHAIN_SYSROOT=/usr/local/osquery-toolchain ..
cmake --build . -j10 # where 10 is the number of parallel build jobs
```

## macOS

The initial directory is assumed to be `/Users/<user>`

### Step 1: Install macOS prerequisites

Please ensure [Homebrew](https://brew.sh/) has been installed, first. Then do the following.

```bash
# Install prerequisites
xcode-select --install
brew install ccache git git-lfs cmake python clang-format flex bison

# Optional: install python tests prerequisites
pip3 install --user setuptools pexpect==3.3 psutil timeout_decorator six thrift==0.11.0 osquery
```

### Step 2: Download and build source on macOS

In the following example, the use of the additional CMake argument `-DCMAKE_OSX_DEPLOYMENT_TARGET=10.11` specifies macOS 10.11 as the minimum compatible macOS version to which you can deploy osquery (this affects the version of the macOS SDK used at build time).

```bash
# Download source
git clone https://github.com/osquery/osquery
cd osquery

# Configure
mkdir build; cd build
cmake -DCMAKE_OSX_DEPLOYMENT_TARGET=10.11 ..

# Build
cmake --build . -j $(sysctl -n hw.ncpu)
```

## Windows 10

The initial directory is assumed to be `C:\`

**Note:** Since Windows and `msbuild` have a 255 characters max path limit, starting the build in the shortest directory path possible is recommended to avoid problems when building.

### Step 1: Install Windows prerequisites

Note: It may be easier to install these prerequisites using [Chocolatey](https://chocolatey.org/).

- [CMake](https://cmake.org/) (>= 3.17.5): the MSI installer is recommended. During installation, select the option to add it to the system `PATH` for all users. If there is any older version of CMake installed (e.g., using Chocolatey), uninstall that version first!  Do not install CMake using the Visual Studio Installer, because it contains an older version than required.
- Visual Studio 2019 (2 options)
  1. [Visual Studio 2019 Build Tools Installer](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=BuildTools&rel=16) (without Visual Studio): In the installer choose the "C++ build tools" workload, then on the right, under "Optional", select "MSVC v142 - VS 2019 C++", "Windows 10 SDK", and "C++ Clang tools for Windows".
  2. [Visual Studio 2019 Community Installer](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&rel=16): In the installer choose the "Desktop development with C++" workload, then on the right, under "Optional", select "MSVC v142 - VS 2019 C++", "Windows 10 SDK", and "C++ Clang tools for Windows".
- [Git for Windows](https://github.com/git-for-windows/git/releases/latest): Select "checkout as-is, commit as-is". Later check "Enable symbolic links" support.
- [Python 3](https://www.python.org/downloads/windows/), specifically the 64-bit version.
- [Wix Toolset](https://wixtoolset.org/releases/)
- [Strawberry Perl](http://strawberryperl.com/) for the OpenSSL formula. It is recommended to install it to the default destination path.
- [7-Zip](https://www.7-zip.org/) if building the Chocolatey package.

### Optional: Install Python tests prerequisites

Python 3 is assumed to be installed in `C:\Program Files\Python37`

```PowerShell
# Using a PowerShell console
& 'C:\Program Files\Python37\python.exe' -m pip install setuptools psutil timeout_decorator thrift==0.11.0 osquery pywin32
```

The use of an Administrator shell is recommended because the build process creates symbolic links. These [require a special permission to create on Windows](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/create-symbolic-links), and the simplest solution is to build as Administrator. If you wish, you can instead assign just the `SeCreateSymbolicLinkPrivilege` permission to the user account. The setting can be found in "Local Security Policy" under Security Settings, Local Policies, User Rights Assignment. The user then has to log out and back in for the policy change to apply.

### Step 2: Download and build source on Windows

```PowerShell
# Using a PowerShell console as Administrator (see note, below)
# Download source
git clone https://github.com/osquery/osquery
cd osquery

# Configure
mkdir build; cd build
cmake -G "Visual Studio 16 2019" -A x64 ..

# Build
cmake --build . --config RelWithDebInfo -j10 # Number of projects to build in parallel
```

## Testing

To build with tests active, add `-DOSQUERY_BUILD_TESTS=ON` to the osquery configure phase, then build the project. CTest will be used to run the tests and give a report.

### Run tests on Windows

To run the tests and get just a summary report:

```PowerShell
cmake --build . --config <RelWithDebInfo|Release|Debug> --target run_tests
```

To get more information when a test fails using PowerShell:

```PowerShell
$Env:CTEST_OUTPUT_ON_FAILURE=1
cmake --build . --config <RelWithDebInfo|Release|Debug> --target run_tests
```

To run a single test, in verbose mode:

```PowerShell
ctest -R <test name> -C <RelWithDebInfo|Release|Debug> -V
```

### Run tests on Linux and macOS

To run the tests and get just a summary report:

```bash
cmake --build . --target test
```

To get more information when a test fails:

```bash
CTEST_OUTPUT_ON_FAILURE=1 cmake --build . --target test
```

To run a single test, in verbose mode:

```bash
ctest -R <testName> -V
```

A "single" test case often still involves dozens or hundreds of unit tests. To run a single _unit test_, you can pass the [`GTEST_FILTER`](https://github.com/google/googletest/blob/master/googletest/docs/advanced.md#running-a-subset-of-the-tests) variable, for example:

```bash
GTEST_FILTER=sharedMemory.* ctest -R <testName> -V #runs just the sharedMemory tests under the <testName> set.
```

## Formatting the code

Osquery uses `clang-format` to format its code, but it's not run on the whole project or files each time; it's run only on the modified lines instead,
using custom scripts.

On Linux the `clang-format` executable is shipped along with the osquery toolchain, and it is the recommended way to run it.  
For the other platforms please refer to their **Install the prerequisites** section if you haven't already.

On Windows remember to update the PATH environment variable with the `clang-format` root folder, so that the scripts can find it.  
You should be able to find `clang-format` folder in the path where you installed either the Build Tools or the full Visual Studio, and from there `VC\Tools\Llvm\bin`.

To verify that all the commits that are present on the branch but not on master are properly formatted, run the following command from the build folder:

```bash
cmake --build . --target format_check
```

This is the same command the CI runs to verify formatting.

If the code is not formatted, you can do so with the following command run from the build folder,
but the code has to be put in the stage area first if it was already committed:

```bash
cmake --build . --target format
```

To avoid having to move the committed files to the stage area and back each time, remember to format the code before committing.

## Running cppcheck

The `cppcheck` tool runs some static analysis checks on the C++ code to detect possible bugs or undefined behaviors.

1. Install the cppcheck prerequisite:
    - On Linux: `apt install cppcheck`
    - On macOS: `brew install cppcheck`
    - On Windows: download and run [the cppcheck MSI installer](https://github.com/danmar/cppcheck/releases).
2. Build the `cppcheck` target: `cmake --build . --target cppcheck`

## Running clang-tidy (Linux only)

The `clang-tidy` executable is shipped along with the osquery toolchain, and it is the recommended way to run it. It is however possible to use the system one, provided it's accessible from the PATH environment variable.

1. When configuring, pass `-DOSQUERY_ENABLE_CLANG_TIDY=ON` to CMake
2. Configure the checks: `-DOSQUERY_CLANG_TIDY_CHECKS=check1,check2` **(optional)**
3. Build osquery

By default, the following checks are enabled:

1. cert-*
2. cppcoreguidelines-*
3. performance-*
4. portability-*
5. readability-*
6. modernize-*
7. bugprone-*

## Using Vagrant

If you are familiar with Vagrant, there is a helpful configuration in the root directory for testing osquery.

### AWS-EC2-Backed Vagrant Targets

The osquery vagrant infrastructure supports leveraging AWS EC2 to run virtual machines.
This capability is provided by the [vagrant-aws](https://github.com/mitchellh/vagrant-aws) plugin, which is installed as follows:

```sh
vagrant plugin install vagrant-aws
```

Before launching an AWS-backed virtual machine, set a few environment variables:

```sh
# Required. Credentials for AWS API. vagrant-aws will error if these are unset.
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
# Name of AWS keypair for launching and accessing the EC2 instance.
export AWS_KEYPAIR_NAME=my-osquery-vagrant-security-group
# Path to local private key for SSH authentication
export AWS_SSH_PRIVATE_KEY_PATH=/path/to/keypair.pem
# Name of AWS security group that allows TCP/22 from vagrant host.
# Leaving this unset may work in some AWS/EC2 configurations.
# If using a non-default VPC use the security group ID instead.
export AWS_SECURITY_GROUP=my-osquery-vagrant-security-group
# Set this to the AWS region, "us-east-1" (default) or "us-west-1".
export AWS_DEFAULT_REGION=...
# Set this to the AWS instance type. If unset, m3.large is used.
export AWS_INSTANCE_TYPE=m3.medium
# (Optional) Set this to the VPC subnet ID.
# (Optional) Make sure your subnet assigns public IPs and there is a route.
export AWS_SUBNET_ID=...
```

Spin up a VM in EC2 and SSH in (remember to suspend/destroy when finished):

```sh
vagrant up aws-amazon2015.03 --provider=aws
vagrant ssh aws-amazon2015.03
```

## Custom Packages

Package creation is facilitated by CPack. Creating a standalone custom package on any platform should be as simple as running:

```sh
cmake --build . --target package
```

Invoking the `package` target will instruct `cpack` to auto resolve all of the package
dependencies for osquery and build a platform specific package. The package created will include several components:

- The executables: `osqueryd`, `osqueryi`, and small management script `osqueryctl`
- An osquery systemd unit on Linux (with initd script wrapper)
- An osquery LaunchDaemon on macOS
- The lenses provided by our Augeas third-party dependency
- A default, or fall-back, OpenSSL certificate store (found within the repository)
- The example query packs from the repository
- Folder structures required for logging

What follows are instructions for directly invoking `cpack` on each platform, should
you wish to create a more custom deployment package. For the most part this is not
encouraged, and users should stick with leveraging the `package` target as detailed above.

### On Linux

To create a DEB, RPM, or TGZ on Linux, CPack will attempt to auto-detect the appropriate package type.
You may override this with the CMake `PACKAGING_SYSTEM` variable as seen in the example below.

Note: RPM will always try to create debuginfo packages, to do so though it needs the source folder
to be in a path that's longer than `/usr/src/debug/osquery/src_0` and the build folder
to be in a path that's longer than `/usr/src/debug/osquery/src_1`.

```sh
cmake -DOSQUERY_TOOLCHAIN_SYSROOT=/usr/local/osquery-toolchain -DPACKAGING_SYSTEM=RPM ..
cmake --build . --target package
```

### On Windows

On Windows CPack will create an MSI by default. You can toggle this behavior to instead create a
Chocolatey package by overriding the CMake `PACKAGING_SYSTEM` variable similar to Linux.

To create a default MSI package use the following:

```sh
cmake -G "Visual Studio 16 2019" -A x64 ..
cmake --build . --config Release --target package
```

To instead generate a Chocolatey package, use the following:

```sh
cmake -DPACKAGING_SYSTEM=NuGet -G "Visual Studio 16 2019" -A x64 ..
cmake --build . --config Release --target package
```

### On macOS

On macOS you can choose between a TGZ or a PKG, which is the default.
You may override this with the CMake `PACKAGING_SYSTEM` variable as seen in the example below.

```sh
cmake -DPACKAGING_SYSTEM=TGZ -DCMAKE_OSX_DEPLOYMENT_TARGET=10.11 ..
cmake --build . --target package
```

## Build Performance

Generating a virtual table should *not* impact system performance. This is easier said than done, as some tables may _seem_ inherently latent (if you expect to run queries like `SELECT * from suid_bin;` which performs a complete filesystem traversal looking for binaries with suid permissions). Please read the osquery features and guide on [performance safety](../deployment/performance-safety.md).

Some quick features include:

- Performance regression and leak detection CI guards.
- Denylisting performance-impacting virtual tables.
- Scheduled query optimization and profiling.
- Query implementation isolation options.
