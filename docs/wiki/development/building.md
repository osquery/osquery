osquery supports many flavors of Linux, FreeBSD, macOS, and Windows.

While osquery runs on a large number of operating systems, we only provide build instructions for a select few.

The supported compilers are: the osquery toolchain (LLVM/Clang 8.0.1) on Linux, MSVC v141 on Windows, and AppleClang from Xcode Command Line Tools 10.2.1.

# Building with CMake

Git (>= 2.14.0), CMake (>= 3.14.6), Python 2, and Python 3 are required to build. The rest of the dependencies are downloaded by CMake.

The default build type is `RelWithDebInfo` (optimizations active + debug symbols) and can be changed in the CMake configure phase by setting the `CMAKE_BUILD_TYPE` flag to `Release` or `Debug`.

The build type is chosen when building on Windows, through the `--config` option, not during the configure phase.

Note: the recommended system memory for building osquery is at least 8GB, or Clang may crash during the compilation of third-party dependencies.

## Linux

The root folder is assumed to be `/home/<user>`

**Ubuntu 18.04/18.10**

```bash
# Install the prerequisites
sudo apt install --no-install-recommends git python python3 bison flex make

# Optional: install python tests prerequisites
sudo apt install --no-install-recommends python3-pip python3-setuptools python3-psutil python3-six python3-wheel
pip3 install timeout_decorator thrift==0.11.0 osquery pexpect==3.3

# Download and install the osquery toolchain
wget https://github.com/osquery/osquery-toolchain/releases/download/1.0.0/osquery-toolchain-1.0.0.tar.xz
sudo tar xvf osquery-toolchain-1.0.0.tar.xz -C /usr/local

# Download and install a newer CMake
wget https://github.com/Kitware/CMake/releases/download/v3.14.6/cmake-3.14.6-Linux-x86_64.tar.gz
sudo tar xvf cmake-3.14.6-Linux-x86_64.tar.gz -C /usr/local --strip 1
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

The root folder is assumed to be `/Users/<user>`

**Step 1: Install the prerequisites**

Please ensure [Homebrew](https://brew.sh/) has been installed, first. Then do the following.

```bash
# Install prerequisites
xcode-select --install
brew install git cmake python@2 python

# Optional: install python tests prerequisites
pip3 install setuptools pexpect==3.3 psutil timeout_decorator six thrift==0.11.0 osquery
```

**Step 2: Download and build**

```bash
# Download source
git clone https://github.com/osquery/osquery
cd osquery

# Configure
mkdir build; cd build
cmake ..

# Build
cmake --build .
```

## Windows 10

The root folder is assumed to be `C:\`

Note: The intention here is to reduce the length of the prefix of the osquery folder, since Windows and msbuild have a 255 characters max path limit.

**Step 1: Install the prerequisites**

Note: It may be easier to install these prerequisites using [Chocolatey](https://chocolatey.org/).

- [CMake](https://cmake.org/) (>= 3.14.6): the MSI installer is recommended. During installation, select the option to add it to the system `PATH` for all users. If there is any older version of CMake installed (e.g., using Chocolatey), uninstall that version first!  Do not install CMake using the Visual Studio Installer, because it contains an older version than required.
- Visual Studio 2019 (2 options)
  1. [Visual Studio 2019 Build Tools Installer](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=BuildTools&rel=16) (without Visual Studio): In the installer choose the "C++ build tools" workload, then on the right, under "Optional", select "MSVC v141 - VS 2017 C++", "MSVC v142 - VS 2017 C++", and "Windows 10 SDK".
  2. [Visual Studio 2019 Community Installer](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&rel=16): In the installer choose the "Desktop development with C++" workload, then on the right, under "Optional", select "MSVC v141 - VS 2017 C++", "MSVC v142 - VS 2017 C++", and "Windows 10 SDK".
- [Git for Windows](https://github.com/git-for-windows/git/releases/latest) (or equivalent)
- [Python 2](https://www.python.org/downloads/windows/), specifically the 64-bit version.
- [Python 3](https://www.python.org/downloads/windows/), specifically the 64-bit version.
- [Wix Toolset](https://wixtoolset.org/releases/)
- [Strawberry Perl](http://strawberryperl.com/) for the OpenSSL formula. It is recommended to install it to the default destination path.
- [7-Zip](https://www.7-zip.org/) if building the Chocolatey package.

**Optional: Install python tests prerequisites**
Python 3 is assumed to be installed in `C:\Program Files\Python37`

```PowerShell
# Using a PowerShell console
& 'C:\Program Files\Python37\python.exe' -m pip install setuptools psutil timeout_decorator thrift==0.11.0 osquery pywin32
```

**Step 2: Download and build**

```PowerShell
# Using a PowerShell console as Administrator (see note, below)
# Download source
git clone https://github.com/osquery/osquery
cd osquery

# Configure
mkdir build; cd build
cmake -G "Visual Studio 16 2019" -A x64 -T v141 ..

# Build
cmake --build . --config RelWithDebInfo -j10 # Number of projects to build in parallel
```

The use of an Administrator shell is recommended because the build process creates symbolic links. These [require a special permission to create on Windows](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/create-symbolic-links), and the simplest solution is to build as Administrator. If you wish, you can instead assign just the `SeCreateSymbolicLinkPrivilege` permission to the user account. The setting can be found in "Local Security Policy" under Security Settings, Local Policies, User Rights Assignment. There is also an opportunity while installing Git for Windows from the official installer (unselected by default) to enable this permission for a specific user, who then has to log out and back in for the policy change to apply.

## Testing

To build with tests active, add `-DOSQUERY_BUILD_TESTS=ON` to the osquery configure phase, then build the project. CTest will be used to run the tests and give a report.

**Run tests on Windows**

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

**Run tests on Linux and macOS**

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

## Running clang-format (Linux and MacOS only)

Note that on Linux the `clang-format` executable is shipped along with the osquery toolchain, and it is the recommended way to run it.

```bash
cmake --build . --target format_check
```

## Running Cppcheck (Linux only)

1. Install it from the distro repository: `apt install cppcheck`
2. Build the **cppcheck** target `cmake --build . --target cppcheck`

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

# Building with Buck

Building and testing is the same on all platforms. Each platform section below describes how to install the required tools and dependencies.

## Linux (Buck)

Install required tools on Ubuntu 18.04 or Ubuntu 18.10:

```bash
sudo apt install openjdk-8-jre clang libc++1 libc++-dev libc++abi1 libc++abi-dev python python3 python3-distutils
```

Install library dependencies:

```bash
sudo apt install liblzma-dev
```

Install `buck`:

```bash
wget 'https://github.com/facebook/buck/releases/download/v2018.10.29.01/buck.2018.10.29.01_all.deb'
sudo apt install ./buck.2018.10.29.01_all.deb
```

## macOS (Buck)

Install required tools using Homebrew:

```bash
xcode-select --install

brew tap caskroom/cask
brew tap caskroom/versions
brew cask install java8
```

Install `buck` and `watchman`. Watchman isn't mandatory, but will make builds faster.

```bash
brew tap facebook/fb
brew install buck watchman
```

## FreeBSD (Buck)

Install required tools on FreeBSD 11.2:

```bash
sudo pkg install openjdk8 python3 python2 clang35
```

Install `buck`:

```bash
sudo curl --output /usr/local/bin/buck 'https://jitpack.io/com/github/facebook/buck/v2018.10.29.01/buck-v2018.10.29.01.pex'
sudo chmod +x /usr/local/bin/buck
```

Install library dependencies:

```bash
sudo pkg install glog thrift thrift-cpp boost-libs magic rocksdb-lite rapidjson zstd linenoise-ng augeas ssdeep sleuthkit yara aws-sdk-cpp lldpd libxml++-2 smartmontools lldpd
```

## Windows 10 (Buck)

You'll need to have the following software installed before you can build osquery on Windows:

- Buck, this also requires the JRE 8 version
- Visual Studio 2017 or greater
- The Windows 10 SDK
- Python3

Once you've installed the above requirements, run `.\tools\generate_buck_config.ps1 -VsInstall '' -VcToolsVersion '' -SdkInstall '' -SdkVersion '' -Python3Path '' -BuckConfigRoot .\tools\buckconfigs\` to generate the buckconfig for building.

## Building and Testing

To build simply run the following command replacing `<platform>` and `<mode>`
appropriately:

```bash
buck build @mode/<platform>/<mode> //osquery:osqueryd
```

When buck finishes find the binary at `buck-out/<mode>/gen/osquery/osqueryd`.

Similarly to run tests just run:

```bash
buck test @mode/<platform>/<mode> //...
```

This will run all tests, you can replace `//...` with a specific target to run specific tests only.

Supported platforms:

- `linux-x86_64`
- `macos-x86_64`
- `windows-x86_64`
- `freebsd-x86_64`

Supported modes:

- `release`
- `debug`

# Using Vagrant

If you are familiar with Vagrant, there is a helpful configuration in the root directory for testing osquery.

## AWS-EC2-Backed Vagrant Targets

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

# Custom Packages

Package creation is facilitated by CPack.

The package will include several components:
- The executables: `osqueryd`, `osqueryi`, and small management script `osqueryctl`
- An osquery systemd unit on Linux (with initd script wrapper)
- An osquery LaunchDaemon on macOS
- The lenses provided by our Augeas third-party dependency
- A default, or fall-back, OpenSSL certificate store (found within the repository)
- The example query packs from the repository
- Folder structures required for logging

To create a DEB, RPM, or TGZ on Linux, CPack will attempt to auto-detect the appropriate package type.
You may override this with the CMake `PACKAGING_SYSTEM` variable as seen in the example below.

```sh
cmake -DPACKAGING_SYSTEM=RPM ..
make package
```

On macOS the `package` target will create a `.pkg`, and on Windows it will create a `.msi`.

# Build Performance

Generating a virtual table should *not* impact system performance. This is easier said than done, as some tables may _seem_ inherently latent (if you expect to run queries like `SELECT * from suid_bin;` which performs a complete filesystem traversal looking for binaries with suid permissions). Please read the osquery features and guide on [performance safety](../deployment/performance-safety.md).

Some quick features include:

- Performance regression and leak detection CI guards.
- Blacklisting performance-impacting virtual tables.
- Scheduled query optimization and profiling.
- Query implementation isolation options.
