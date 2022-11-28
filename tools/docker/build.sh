#!/bin/bash

build_deb() {
    VERSION=$1
    OS=$2

    TAG=$(echo $OS | sed 's/://g')

    docker build -f deb-dockerfile . --build-arg OSQUERY_URL=https://pkg.osquery.io/deb/osquery_${VERSION}-1.linux_amd64.deb --build-arg OS_IMAGE=$OS -t osquery/osquery:${VERSION}-${TAG}
}

build_rpm() {
    VERSION=$1
    OS=$2

    TAG=$(echo $OS | sed 's/://g')

    docker build -f rpm-dockerfile . --build-arg OSQUERY_URL=https://pkg.osquery.io/rpm/osquery-${VERSION}-1.linux.x86_64.rpm --build-arg OS_IMAGE=$OS -t osquery/osquery:${VERSION}-${TAG}
}

versions='5.2.3'
deb_platforms='ubuntu:16.04 ubuntu:18.04 ubuntu:20.04 ubuntu:22.04 debian:10 debian:9 debian:8 debian:7'
rpm_platforms='centos:6 centos:7 centos:8'

for v in $versions
do
    for os in $deb_platforms
    do
        build_deb $v $os
    done

    for os in $rpm_platforms
    do
        build_rpm $v $os
    done
done
