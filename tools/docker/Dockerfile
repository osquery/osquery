FROM ubuntu:14.04
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get install -y \
    git \
    wget \
    ruby \
    ruby-dev \
    python \
    python-dev \
    build-essential \
    curl
# create dev user
RUN adduser --ingroup sudo --disabled-password --gecos '' dev && \
    mkdir -p /home/dev && \
    sed -i.bak 's/sudo\tALL=(ALL:ALL) ALL/sudo\tALL=(ALL:ALL) NOPASSWD: ALL/g' /etc/sudoers && \
    mkdir -p /usr/local/osquery && \
    chown -R dev /usr/local && \
    mkdir -p /osquery && \
    chown -R dev /osquery
# fix locales
RUN \
    locale-gen en_US.UTF-8 && \
    localedef en_US.UTF-8 -i en_US -fUTF-8 && \
    dpkg-reconfigure locales && \
    echo "LANG=en_US.UTF-8" >> /etc/default/locale && \
    echo "LANGUAGE=en_US.UTF-8" >> /etc/default/locale && \
    echo "LC_ALL=en_US.UTF-8" >> /etc/default/locale && \
    export LANG=en_US.UTF-8 && \
    export LANGUAGE=en_US.UTF-8 && \
    export LC_ALL=en_US.UTF-8 && \
    LANG=en_US.UTF-8 && \
    LANGUAGE=en_US.UTF-8 && \
    LC_ALL=en_US.UTF-8 && \
    echo "en_US.UTF-8 UTF-8" > /etc/locale.gen && \
    locale-gen
USER dev
ENV HOME /home/dev
RUN git clone https://github.com/facebook/osquery.git
RUN sudo chown -R dev /osquery
WORKDIR /osquery
RUN ./tools/provision.sh
RUN make
RUN sudo make install
#
USER root
WORKDIR /osquery/build/linux/osquery
#
RUN mkdir -p /var/osquery && mkdir -p /var/log/osquery
#
CMD ["osqueryd", "--config_path=/etc/osquery/osquery.conf", "--verbose"]
