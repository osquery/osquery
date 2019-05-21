# Building osquery

## Provisioning

Start by provisioning your machine following the steps bellow according to your
operating system.

### macOS

*Install tools*

```
xcode-select --install

brew tap caskroom/cask
brew tap caskroom/versions
brew cask install java8
```

*Install Buck and Watchman*

Watchman isn't mandatory but will make builds faster.

```
brew tap facebook/fb
brew install buck watchman
```

### Ubuntu 18.04 / 18.10

*Install tools*

```
sudo apt install openjdk-8-jre clang libc++1 libc++-dev libc++abi1 libc++abi-dev python python3 python3-distutils
```

*Install dependencies*

```
sudo apt install liblzma-dev
```

*Install Buck*

```
wget 'https://github.com/facebook/buck/releases/download/v2018.10.29.01/buck.2018.10.29.01_all.deb'
sudo apt install ./buck.2018.10.29.01_all.deb
```

### FreeBSD 11.2

*Install tools*

```
sudo pkg install openjdk8 python3 python2 clang35
```

*Install Buck*

```
sudo curl --output /usr/local/bin/buck 'https://jitpack.io/com/github/facebook/buck/v2018.10.29.01/buck-v2018.10.29.01.pex'
sudo chmod +x /usr/local/bin/buck
```

*Install dependencies*

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

## Build & Test

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
