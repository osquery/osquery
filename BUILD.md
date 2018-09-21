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

Install Visual Studio 2017. It might work with previous versions but was not
tested yet.

Currently, the toolchain paths are hard-coded for Visual Studio 2017 `15.5` with
MSVC `14.12.25827` and Windows SDK `10.0.12299.91`. If your setup doesn't match
these exact versions you need to update the paths under
`tools/buckconfigs/windows-x86_64/toolchain/vs2017_15.5.bcfg`. You can also
create a new `bcfg` file there and update the mode files under
`mode/windows-x86_64/`. Finding the toolchain path will soon be automated.


## Build

To build simply run the following command replacing `<platform>` and `<mode>`
appropriately:

```
buck build @mode/<platform>/release osquery:osqueryd
```

When buck finishes find the binary at `buck-out/<mode>/gen/osquery/osqueryd`.

Supported platforms:

* `linux-x86_64`
* `macos-x86_64`
* `windows-x86_64`
* `freebsd-x86_64`

Supported modes:

* `release`
* `debug`
