FROM ubuntu:18.04
COPY *.deb ./
RUN apt update -q -y && apt upgrade -q -y && apt install -q -y --no-install-recommends \
  git \
  make \
  cppcheck \
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
  python3-setuptools \
  python3-psutil \
  python3-pip \
  python3-six \
  rpm \
  dpkg-dev \
  file \
  elfutils \
  locales \
  python3-wheel \
&& dpkg -i linux-base_1.0_all.deb linux-firmware_1.0_all.deb linux-generic_1.0_all.deb \
&& apt clean && rm -rf /var/lib/apt/lists/* \
&& sudo pip3 install timeout_decorator thrift==0.11.0 osquery pexpect==3.3 docker
RUN cd ~ && wget https://github.com/Kitware/CMake/releases/download/v3.17.5/cmake-3.17.5-Linux-x86_64.tar.gz \
&& sudo tar xvf cmake-3.17.5-Linux-x86_64.tar.gz -C /usr/local --strip 1 && rm cmake-3.17.5-Linux-x86_64.tar.gz \
&& wget https://github.com/osquery/osquery-toolchain/releases/download/1.1.0/osquery-toolchain-1.1.0-x86_64.tar.xz \
&& sudo tar xvf osquery-toolchain-1.1.0-x86_64.tar.xz -C /usr/local && rm osquery-toolchain-1.1.0-x86_64.tar.xz
RUN locale-gen en_US.UTF-8
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8'
