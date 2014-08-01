#!/bin/bash

function error
{
    echo -e "\033[1;31m${1}\033[0m" 1>&2
}

function checkRequireRootUser
{
    if [[ "$(whoami)" != 'root' ]]
    then
        error "ERROR: please run this program as 'root'"
        exit 1
    fi
}

is_ubuntu() {
  uname -a | grep Ubuntu 2>&1  1>/dev/null
  return $?
}

curl_installed() {
  which curl 2>&1  1>/dev/null
  return $?
}

function installChef()
{
    if [[ "$(which chef-client)" = '' ]]
    then
        local chefProfilePath='/etc/profile.d/chef.sh'

        if [ is_ubuntu ] && [ !curl_installed ]; then
            apt-get install -y curl
        fi

        curl -s -L 'https://www.opscode.com/chef/install.sh' | bash && \
        echo 'export PATH="/opt/chef/embedded/bin:$PATH"' > "${chefProfilePath}" && \
        source "${chefProfilePath}"
    fi
}

function main()
{
    checkRequireRootUser
    installChef
}

main
