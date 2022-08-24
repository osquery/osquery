# Building osquery from source

osquery supports many flavors of Linux, macOS, and Windows.

While osquery runs on a large number of operating systems, we only provide build instructions for a select few.

The supported compilers are: the osquery toolchain (LLVM/Clang 9.0.1) on Linux, MSVC v142 on Windows, and AppleClang from Xcode Command Line Tools 11.7.

## Prerequisites

Git (>= 2.14.0), CMake (>= 3.21.4), Python 3 are required to build. The rest of the dependencies are downloaded by CMake.

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
export ARCH=$(uname -m) # There is toolchain support for x86_64 and aarch64.
wget https://github.com/osquery/osquery-toolchain/releases/download/1.1.0/osquery-toolchain-1.1.0-${ARCH}.tar.xz
sudo tar xvf osquery-toolchain-1.1.0-${ARCH}.tar.xz -C /usr/local

# Download and install a newer CMake.
# Afterward, verify that `/usr/local/bin` is in the `PATH` and comes before `/usr/bin`.
wget https://cmake.org/files/v3.21/cmake-3.21.4-linux-${ARCH}.tar.gz
sudo tar xvf cmake-3.21.4-linux-${ARCH}.tar.gz -C /usr/local --strip 1

# Download source
git clone https://github.com/osquery/osquery
cd osquery

# Build osquery
mkdir build; cd build
cmake -DOSQUERY_TOOLCHAIN_SYSROOT=/usr/local/osquery-toolchain ..
cmake --build . -j10 # where 10 is the number of parallel build jobs
```

## macOS

The current build of osquery supports deployment to the same set of macOS versions (macOS 10.14 and newer).  _Building_
osquery from source on macOS now requires 10.15 Catalina or newer.

The initial directory is assumed to be `/Users/<user>`

### Step 1: Install macOS prerequisites

Please ensure [Homebrew](https://brew.sh/) has been installed, and install a _full copy_ of Xcode 12 or newer (not just the Xcode command-line tools, although you need to install those too — launch Xcode after installing or upgrading, and complete its installation of the "additional components" when prompted).

Then do the following.

```bash
# Install prerequisites
xcode-select --install
brew install ccache git git-lfs cmake python clang-format flex bison

# Optional: install python tests prerequisites
pip3 install --user setuptools pexpect==3.3 psutil timeout_decorator six thrift==0.11.0 osquery
```

### Step 2: Download and build source on macOS

In the following example, the use of the additional CMake argument `-DCMAKE_OSX_DEPLOYMENT_TARGET=10.14` specifies macOS 10.14 as the minimum compatible macOS version to which you can deploy osquery (this affects the version of the macOS SDK used at build time).

```bash
# Download source
git clone https://github.com/osquery/osquery
cd osquery

# Configure
mkdir build; cd build
cmake -DCMAKE_OSX_DEPLOYMENT_TARGET=10.14 -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ ..

# Build
cmake --build . -j $(sysctl -n hw.ncpu)
```

### Features Requiring Special Build Entitlements

Certain functionality on macOS requires an entitled and code-signed executable. By default, macOS builds from source will be _unsigned_ and these particular features will be disabled at runtime.

Specifically, the `es_process_events` table makes use of the EndpointSecurity APIs, which require osquery to be code-signed with a certificate possessing the EndpointSecurity Client entitlement. If unsigned, osquery will still run as normal, but `es_process_events` will be disabled.

Organizations wishing to code-sign osquery themselves will need their Apple Developer team _account owner_ to manually request and obtain the EndpointSecurity Client entitlement from Apple, for their organization's code-signing certificate. Developers can also disable SIP in a development VM (disabling SIP decreases your system's security and is _not_ recommended except on a VM dedicated to building osquery) and use ad-hoc code-signing, if they want to work on `es_process_events` without pursuing the entitlement.

If using VMware Fusion 12, for example, you can reach Recovery Mode by going to Virtual Machine, Settings, Startup Disk. There, hold the Option key, and click `Restart to Firmware...`. Restarting the VM will now enter the VMware virtual EFI shell. From here, select `Enter Setup`, `Boot from a File`, and then arrow down to the Recovery partition. Hit return to find and select the `boot.efi`, and hit return again to enter Recovery Mode. From a Terminal in Recovery Mode, you can [disable SIP](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html) and then reboot to macOS.

## Windows 10

The initial directory is assumed to be `C:\`

**Note:** Windows and `msbuild` have traditionally had a 260 character max path limit. If you encounter problems with the long paths generated by CMake, we recommend building in a shorter path, like `C:\Projects\osquery`. If that still isn't working, since Windows 10 since Version 1607 there is a registry key that can enable longer paths. From an elevated command prompt:

`REG ADD HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v LongPathsEnabled /t REG_DWORD /d 1 /f`

After changing that key, reboot your build machine and re-attempt the build.

### Step 1: Install Windows prerequisites

Note: It may be easier to install these prerequisites using [Chocolatey](https://chocolatey.org/).

- [CMake](https://cmake.org/) (>= 3.21.4): the MSI installer is recommended. During installation, select the option to add it to the system `PATH` for all users. If there is any older version of CMake installed (e.g., using Chocolatey), uninstall that version first!  Do not install CMake using the Visual Studio Installer, because it contains an older version than required.
- Visual Studio 2019 (2 options)
  1. [Visual Studio 2019 Build Tools Installer](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=BuildTools&rel=16) (without Visual Studio): In the installer choose the "C++ build tools" workload, then on the right, under "Optional", select "MSVC v142 - VS 2019 C++", "Windows 10 SDK", and "C++ Clang tools for Windows".
  2. [Visual Studio 2019 Community Installer](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&rel=16): In the installer choose the "Desktop development with C++" workload, then on the right, under "Optional", select "MSVC v142 - VS 2019 C++", "Windows 10 SDK", and "C++ Clang tools for Windows".
- [Git for Windows](https://github.com/git-for-windows/git/releases/latest): Select "checkout as-is, commit as-is". Later check "Enable symbolic links" support.
- [Python 3](https://www.python.org/downloads/windows/), specifically the 64-bit version.
- [Wix Toolset](https://wixtoolset.org/releases/)
- [Strawberry Perl](https://strawberryperl.com/) for the OpenSSL formula. It is recommended to install it to the default destination path.
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

A "single" test case often still involves dozens or hundreds of unit tests. To run a single _unit test_, you can pass the [`GTEST_FILTER`](https://github.com/google/googletest/blob/master/googletest/docs/advanced.md#running-a-subset-of-the-tests) variable, for example:

```PowerShell
$Env:GTEST_FILTER='windowsEventLog.*'
ctest -R tests_integration_tests_tables-test -C RelWithDebInfo -V #runs just the windowsEventLog under the integration tables tests
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

## Building packages

The packaging logic is now in a separate repository, [osquery-packaging](https://github.com/osquery/osquery-packaging). Packages are created in two steps:

1. Create the package data from osquery/osquery
2. Use the osquery/osquery-packaging logic to create the actual packages

This approach allows maintainers to easily re-generate all the officially supported packages without going through the whole build process, which is especially useful when applying code signing from a protected machine.

### Generating the package data

1. Build osquery
2. Create a destination folder and set its path in the `DESTDIR` environment variable
3. Run the `install` target

```sh
cd build_folder
mkdir package_data
export DESTDIR=$(pwd)/package_data  # on Windows: `set DESTDIR=path` or `$Env:DESTDIR=path` for PowerShell
cmake --build . --target install    # on Windows: add --config Release
```

The newly created folder will include several components:

- The executables: `osqueryd`, `osqueryi`
- The lenses provided by our Augeas third-party dependency
- A default, or fall-back, OpenSSL certificate store (found within the repository)
- The example query packs from the repository
- Folder structures required for logging
- Windows: small management scripts: `osqueryctl` and `manage-osqueryd.ps1`
- Linux: systemd units, with initd script wrappers
- macOS: a LaunchDaemon unit
- Package control files (i.e.: deb-specific configurations, XML data required by WIX to generate MSI, etc..)

### Identifying the osquery version

**Linux, macOS**

```sh
cd osquery_source_folder
git fetch --tags

export OSQUERY_VERSION=$(git describe --tags --always)
```

**Windows**

```batch
cd osquery_source_folder

git fetch --tags
git describe --tags --abbrev=0

set OSQUERY_VERSION=<version_here>
```

### Preparing to build the osquery-packaging repository

Pre-requisites (for RPM builds):

```sh
sudo apt install binutils elfutils
```

Generating an RPM package:

```sh
git clone https://github.com/osquery/osquery-packaging

mkdir build
cd build
```

Common input parameters

 - **OSQUERY_VERSION**: can be customized, but we usually use the output of `git describe --always`
 - **OSQUERY_DATA_PATH**: Where the package data has been installed

### Creating the Linux packages

When generating packages, the install path for osquery is determined by `CMAKE_INSTALL_PREFIX` (default:
 `/usr/local/`) when building the TGZ "package", and `CMAKE_PACKAGING_INSTALL_PREFIX` (default: `/usr/`)
  when building either the DEB or RPM packages.

Linux-specific parameters:

 - **CPACK_GENERATOR**: Either `DEB`, `RPM` or `TGZ`
 - **OSQUERY_SOURCE_DIRECTORY_LIST**: An optional list of paths, populated when creating the debuginfo and dbgsym packages for DEB/RPM. Pass the source and the build folders of osquery if you want to generate them.

*Note: RPM will always try to create debuginfo packages, to do so though it needs the source folder to be in a path that's longer than `/usr/src/debug/osquery/src_0` and the build folder to be in a path that's longer than `/usr/src/debug/osquery/src_1`.*

```sh
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCPACK_GENERATOR=DEB \
  -DOSQUERY_PACKAGE_VERSION=${OSQUERY_VERSION} \
  -DOSQUERY_DATA_PATH=${DESTDIR} \
  -DOSQUERY_SOURCE_DIRECTORY_LIST="osquery-src-path;osquery-build-path" \
  ../osquery-packaging

cmake --build . --target package
```

### Creating the Windows packages

Windows-specific parameters:

 - **CPACK_GENERATOR**: Either `WIX` or `NuGet`
 - **OSQUERY_BITNESS**: Either 32 or 64, depending on which architecture has been built

*Note: Please note that the NuGet and WIX generators only support the `a.b.c` version format. If the commit being built is not tagged, consider using `git describe --tags --abbrev=0`*

```batch
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

cmake -DCMAKE_BUILD_TYPE=Release ^
  -DCPACK_GENERATOR=WIX ^
  -DOSQUERY_PACKAGE_VERSION=%OSQUERY_VERSION% ^
  -DOSQUERY_DATA_PATH=%DESTDIR% ^
  -DOSQUERY_BITNESS=64 ^
  ..\osquery-packaging

cmake --build . --config Release --target package
```

### Creating the macOS packages

macOS-specific parameters:

 - **CPACK_GENERATOR**: Either `productbuild` (PKG  files) or `TGZ`

```sh
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCPACK_GENERATOR=productbuild \
  -DOSQUERY_PACKAGE_VERSION=${OSQUERY_VERSION} \
  -DOSQUERY_DATA_PATH=${DESTDIR} \
  ../osquery-packaging

cmake --build . --target package
```

## Build Performance

Generating a virtual table should *not* impact system performance. This is easier said than done, as some tables may _seem_ inherently latent (if you expect to run queries like `SELECT * from suid_bin;` which performs a complete filesystem traversal looking for binaries with suid permissions). Please read the osquery features and guide on [performance safety](../deployment/performance-safety.md).

Some quick features include:

- Performance regression and leak detection CI guards.
- Denylisting performance-impacting virtual tables.
- Scheduled query optimization and profiling.
- Query implementation isolation options.
