#!/usr/bin/env bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export PATH="$PATH:/usr/local/bin"

. $SCRIPT_DIR/lib.sh

BREW_PACKAGES=(rocksdb boost gflags glog thrift)
BREW_PREFIX=`brew --prefix`
BREW_CELLAR=`brew --cellar`

function main() {
  platform OS
  if [[ ! "$OS" = "darwin" ]]; then
    fatal "This script must be ran on OS X"
  fi

  dependency_list=("${BREW_PACKAGES[@]}")
  for package in ${BREW_PACKAGES[*]}; do
    for dep in `brew deps $package`; do
      if ! contains_element $dep "${dependency_list[@]}"; then
        dependency_list+=($dep)
      fi
    done
  done

  for dep in ${dependency_list[*]}; do
    dep_dir=`brew info $dep | grep Cellar | awk '{print $1}'`
    brew unlink $dep 2>&1  1>/dev/null
    links=`brew link --dry-run $dep`
    brew link --overwrite $dep 2>&1  1>/dev/null
    echo "    - $dep ($dep_dir)"
    for link in $links; do
      if [[ $link = $BREW_PREFIX* ]]; then
        target="`dirname $link`/`ls -l $link | awk '{print $11}'`"
        echo "      - $link => $target"
      fi
    done
  done
}

main
