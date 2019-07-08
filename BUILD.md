# Building osquery

## Using CMake

osquery supports Linux (Ubuntu 18.04/18.10), macOS, and Windows.

git, CMake (>= 3.13.3), clang 6.0, Python 2, and Python 3 are required to build. The rest of the dependencies are downloaded by CMake.

The default build type is `RelWithDebInfo` (optimizations active + debug symbols) and can be changed in the CMake configure phase by setting the `CMAKE_BUILD_TYPE` flag to `Release` or `Debug`.

The build type is chosen when building on Windows, not during the configure phase, through the `--config` option.

### Linux

The root folder is assumed to be `/home/<user>`

**Ubuntu 18.04**

```
# Install the prerequisites
sudo apt install git llvm clang libc++-dev libc++abi-dev liblzma-dev python python3

# Download and install a newer CMake
wget https://github.com/Kitware/CMake/releases/download/v3.14.5/cmake-3.14.5-Linux-x86_64.tar.gz
sudo tar xvf cmake-3.14.5-Linux-x86_64.tar.gz -C /usr/local --strip 1
# Verify that `/usr/local/bin` is in the `PATH` and comes before `/usr/bin`

# Download and build osquery
git clone https://github.com/osquery/osquery
mkdir build; cd build
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ ..
cmake --build . -j10 # where 10 is the number of parallel build jobs
```

**Ubuntu 18.10**

```
# Install the prerequisites
sudo apt install git llvm-6.0 clang-6.0 libc++-dev libc++abi-dev liblzma-dev python python3

# Download and install a newer CMake
wget https://github.com/Kitware/CMake/releases/download/v3.14.5/cmake-3.14.5-Linux-x86_64.tar.gz
sudo tar xvf cmake-3.14.5-Linux-x86_64.tar.gz -C /usr/local --strip 1
# Verify that `/usr/local/bin` is in the `PATH` and comes before `/usr/bin`

# Download and build osquery
git clone https://github.com/osquery/osquery
mkdir build; cd build
cmake -DCMAKE_C_COMPILER=clang-6.0 -DCMAKE_CXX_COMPILER=clang++-6.0 ..
cmake --build . -j10 # where 10 is the number of parallel build jobs
```

### Windows

The root folder is assumed to be `C:\Users\<user>`

**Step 1: Install the prerequisites**

- [CMake](https://cmake.org/) (>= 3.14.4): be sure to put it into the `PATH`
- [Build Tools for Visual Studio 2019](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=BuildTools&rel=16): from the installer choose the C++ build tools workload, then on the right, under Installation details, also check MSVC v141
- [Git for Windows](https://github.com/git-for-windows/git/releases/latest) (or equivalent)
- [Python 2](https://www.python.org/downloads/windows/)
- [Python 3](https://www.python.org/downloads/windows/)

**Step 2: Download and build**

```
# Download using a PowerShell console
git clone https://github.com/osquery/osquery

# Configure
mkdir build; cd build
cmake -G "Visual Studio 16 2019" -A x64 -T v141 ..

# Build
cmake --build . --config RelWithDebInfo -j10 # Number of projects to build in parallel
```

### MacOS

Please ensure [homebrew](https://brew.sh/) has been installed. The root folder is assumed to be `/Users/<user>`

```
# Install prerequisites
brew install git cmake python@2 python

# Download and build
git clone https://github.com/osquery/osquery

# Configure
mkdir build; cd build
cmake ..

# Build
cmake --build . -j10 # where 10 is the number of parallel build jobs
```

### Tests

To build with tests active, add `-DBUILD_TESTING=ON` to the osquery configure phase, then build the project. CTest will be used to run the tests and give a report.

**Run tests on Windows**

To run the tests and get just a summary report:\
`cmake --build . --config <RelWithDebInfo|Release|Debug> --target run_tests`

To get more information when a test fails using powershell:

```
$Env:CTEST_OUTPUT_ON_FAILURE=1
cmake --build . --config <RelWithDebInfo|Release|Debug> --target run_tests
```

To run a single test, in verbose mode:\
`ctest -R <test name> -C <RelWithDebInfo|Release|Debug> -V`

**Run tests on Linux/MacOS**

To run the tests and get just a summary report:\
`cmake --build . --target test`

To get more information when a test fails:\
`CTEST_OUTPUT_ON_FAILURE=1 cmake --build . --target test`

To run a single test, in verbose mode:\
`ctest -R <test name> -V`

## Using Buck

Building and testing is the same on all platforms. Each platform section below describes how to install the required tools and dependencies.

### Ubuntu 18.04 and 18.10

Install required tools

```
sudo apt install openjdk-8-jre clang libc++1 libc++-dev libc++abi1 libc++abi-dev python python3 python3-distutils
```

Install library dependencies

```
sudo apt install liblzma-dev
```

Install `buck`

```
wget 'https://github.com/facebook/buck/releases/download/v2018.10.29.01/buck.2018.10.29.01_all.deb'
sudo apt install ./buck.2018.10.29.01_all.deb
```

### MacOS

Install required tools using Homebrew

```
xcode-select --install

brew tap caskroom/cask
brew tap caskroom/versions
brew cask install java8
```

Install `buck` and `watchman`. Watchman isn't mandatory but will make builds faster.

```
brew tap facebook/fb
brew install buck watchman
```

### FreeBSD 11.2

Install required tools

```
sudo pkg install openjdk8 python3 python2 clang35
```

Install `buck`

```
sudo curl --output /usr/local/bin/buck 'https://jitpack.io/com/github/facebook/buck/v2018.10.29.01/buck-v2018.10.29.01.pex'
sudo chmod +x /usr/local/bin/buck
```

Install library dependencies

```
sudo pkg install glog thrift thrift-cpp boost-libs magic rocksdb-lite rapidjson zstd linenoise-ng augeas ssdeep sleuthkit yara aws-sdk-cpp lldpd libxml++-2 smartmontools lldpd
```

### Windows 10

You'll need to have the following software installed before you can build osquery on Windows:

* Buck, this also requires the JRE 8 version
* Visual Studio 2017 or greater
* The Windows 10 SDK
* Python3

Once you've installed the above requirements, run `.\tools\generate_buck_config.ps1 -VsInstall '' -VcToolsVersion '' -SdkInstall '' -SdkVersion '' -Python3Path '' -BuckConfigRoot .\tools\buckconfigs\` to generate the buckconfig for building.

### Build & Test

To build simply run the following command replacing `<platform>` and `<mode>`
appropriately:

```
buck build @mode/<platform>/<mode> //osquery:osqueryd
```

When buck finishes find the binary at `buck-out/<mode>/gen/osquery/osqueryd`.

Similarly to run tests just run:

```
buck test @mode/<platform>/<mode> //...
```

This will run all tests, you can replace `//...` with a specific target to run specific tests only.

Supported platforms:

* `linux-x86_64`
* `macos-x86_64`
* `windows-x86_64`
* `freebsd-x86_64`

Supported modes:

* `release`
* `debug`

## Building prebuilt dependencies

"Prebuilt" versions of the dependency libraries are provided for Linux, MacOS, and Windows. This means you only need to install the required tooling.

"Prebuilt" or "prebuilds" are versions of library dependencies pre-built using our logic in CMake within the third-party folder. We use CMake's `ExternalProject` and a custom `PREFIX`, or install location, set to the `third-party-prebuilt` submodule. These configurations should be supported on MacOS, Linux, and Windows.

An individual library can be built using:

```
mkdir -p build/deps && cd build/deps
cmake ../..
cmake --build . --config Release --target thirdparty_build_LIBRARY
```

Or all libraries can be built using

```
cmake --build . --config Release --target thirdparty_prebuilt
```

### MacOS

Prebuilt libraries use the system toolchain and operating system version support flags set to `10.13` (subject to change).

Use the prebuilt building helper script. It optionally uses a `STATIC_ENFORCE` environent variable to enforce that the location of the osquery clone and the location of the toolchain are well-known. This is required for reproducible building.

```
./tools/build_prebuilt.sh
```

### Linux

**Portable toolchain**

Since there are many Linux distributions we use a static toolchain for building dependencies. This helps achieve a reproducible build and makes debugging easier. You may use any toolchain you like.

Pay attention to the portability aspect of the toolchain. What runtime/dynamic linking requirements does it impose on the output executables.

```
sudo apt-get install automake pkg-config libtool autopoint bison flex xsltproc texinfo
wget https://github.com/Kitware/CMake/releases/download/v3.14.5/cmake-3.14.5-Linux-x86_64.tar.gz
sudo tar xvf cmake-3.14.5-Linux-x86_64.tar.gz -C /usr/local --strip 1

mkdir ~/toolchains; cd ~/toolchains
wget https://github.com/theopolis/build-anywhere/releases/download/v5/x86_64-anywhere-linux-gnu-v5.tar.xz
tar xf x86_64-anywhere-linux-gnu-v5.tar.xz
source ./x86_64-anywhere-linux-gnu/scripts/anywhere-setup.sh
```

Use the prebuilt building helper script. It optionally uses a `STATIC_ENFORCE` environent variable to enforce that the location of the osquery clone and the location of the toolchain are well-known. This is required for reproducible building.

```
./tools/build_prebuilt.sh
```
