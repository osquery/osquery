FROM ubuntu:18.04
COPY *.deb ./
RUN apt update -q -y && apt upgrade -q -y && apt install -q -y --no-install-recommends \
  git \
  make \
  ccache \
  python \
  python3 \
  sudo \
  wget \
  ca-certificates \
  tar \
  icu-devtools \
  flex \
  bison \
  xz-utils \
  python-setuptools \
  python-pexpect \
  python-psutil \
  python-pip \
  python-six \
&& dpkg -i linux-base_1.0_all.deb linux-firmware_1.0_all.deb linux-generic_1.0_all.deb \
&& apt clean && rm -rf /var/lib/apt/lists/* \
&& sudo pip install timeout_decorator
RUN cd ~ && wget https://github.com/Kitware/CMake/releases/download/v3.14.6/cmake-3.14.6-Linux-x86_64.tar.gz \
&& sudo tar xvf cmake-3.14.6-Linux-x86_64.tar.gz -C /usr/local --strip 1 && rm cmake-3.14.6-Linux-x86_64.tar.gz \
&& wget https://github.com/osquery/osquery-toolchain/releases/download/1.0.0/osquery-toolchain-1.0.0.tar.xz \
&& sudo tar xvf osquery-toolchain-1.0.0.tar.xz -C /usr/local && rm osquery-toolchain-1.0.0.tar.xz
