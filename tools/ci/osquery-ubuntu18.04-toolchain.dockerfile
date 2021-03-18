FROM ubuntu:18.04 AS ubuntubase
RUN apt update -q -y
RUN apt upgrade -q -y

FROM ubuntubase AS cmakebuild
# Due to https://github.com/osquery/osquery/pull/6801 we build our own cmake. :<
# (This takes about 2 hours to run in dockerx aarch64 emulation)
RUN apt install -q -y wget gcc g++ libssl-dev make

RUN wget https://github.com/Kitware/CMake/releases/download/v3.17.5/cmake-3.17.5.tar.gz
RUN tar zxvf cmake-3.17.5.tar.gz
RUN cd cmake-3.17.5 \
	&& ./bootstrap -- -DCMAKE_BUILD_TYPE:STRING=Release \
	&& make -j`nproc` \
	&& make install

RUN rm -rf /usr/local/doc /usr/local/bin/cmake-gui

FROM ubuntubase AS base1
COPY --from=cmakebuild /usr/local /usr/local

RUN apt install -q -y --no-install-recommends \
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
	python3-wheel

RUN pip3 install timeout_decorator thrift==0.11.0 osquery pexpect==3.3 docker

FROM base1 AS base2
RUN case $(uname -m) in aarch64) ARCH="aarch64" ;; amd64|x86_64) ARCH="x86_64" ;; esac \
	&& wget https://github.com/osquery/osquery-toolchain/releases/download/1.1.0/osquery-toolchain-1.1.0-${ARCH}.tar.xz \
	&& sudo tar xvf osquery-toolchain-1.1.0-${ARCH}.tar.xz -C /usr/local \
	&& rm osquery-toolchain-1.1.0-${ARCH}.tar.xz

FROM base2 as base3
# When we stop building our own cmake, we can use this...
# ENV cmakeVer 3.19.6
#RUN case $(uname -m) in aarch64) ARCH="aarch64" ;; amd64|x86_64) ARCH="x86_64" ;; esac \
#	&& wget https://github.com/Kitware/CMake/releases/download/v${cmakeVer}/cmake-${cmakeVer}-Linux-${ARCH}.tar.gz \
#	&& sudo tar xvf cmake-${cmakeVer}-Linux-${ARCH}.tar.gz -C /usr/local --strip 1 \
#	&& rm cmake-${cmakeVer}-Linux-${ARCH}.tar.gz

FROM base3 AS base4
RUN locale-gen en_US.UTF-8

RUN apt autoremove --purge -y
RUN rm -rf /usr/local/doc /usr/local/bin/cmake-gui
RUN apt clean
RUN rm -rf /var/lib/apt/lists/*

# Squash all layers down using a giant COPY. It's kinda gross, but it
# works. Though the layers are only adding about 50 megs on a 1gb
# image.
FROM scratch AS builder
COPY --from=base4 / /
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8'
