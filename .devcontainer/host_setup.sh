#!/bin/sh

set -e

# Prepare to install packages
sudo apt update

# Install the prerequisites
sudo apt install -y --no-install-recommends wget sudo xz-utils nano bc git python3 bison flex make cppcheck gdb

# Optional: install python tests prerequisites
sudo apt install -y --no-install-recommends python3-pip python3-setuptools python3-psutil python3-six python3-wheel
pip3 install timeout_decorator thrift==0.11.0 osquery pexpect==3.3

# Optional: install RPM packaging prerequisites
sudo apt install -y --no-install-recommends rpm binutils

# Download and install the osquery toolchain
sudo apt install -y jq
version=$(curl https://api.github.com/repos/osquery/osquery-toolchain/releases | jq -r '.[0].tag_name')
wget -O /tmp/osquery-toolchain.tar.xz https://github.com/osquery/osquery-toolchain/releases/download/${version}/osquery-toolchain-${version}-$(uname -m).tar.xz
sudo tar xvf /tmp/osquery-toolchain.tar.xz -C /usr/local

# Download and install a newer CMake.
# Afterward, verify that `/usr/local/bin` is in the `PATH` and comes before `/usr/bin`.
wget -O /tmp/cmake-3.21.4-linux-$(uname -m).tar.gz https://cmake.org/files/v3.21/cmake-3.21.4-linux-$(uname -m).tar.gz
sudo tar xvf /tmp/cmake-3.21.4-linux-$(uname -m).tar.gz -C /usr/local --strip 1
