#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

# 1: Path to install brew into
# 2: Linux or Darwin
function setup_brew() {
  DEPS="$1"
  BREW_TYPE="$2"
  ACTION="$3"

  if [[ "$BREW_TYPE" == "linux" ]]; then
    BREW_REPO=$LINUXBREW_REPO
    BREW_COMMIT=$LINUXBREW_BREW
    CORE_COMMIT=$LINUXBREW_CORE
  else
    BREW_REPO=$HOMEBREW_REPO
    BREW_COMMIT=$HOMEBREW_BREW
    CORE_COMMIT=$HOMEBREW_CORE
  fi

  # Checkout new brew in local deps dir
  if [[ ! -d "$DEPS/.git" ]]; then
    log "setting up new brew in $DEPS"
    git clone $BREW_REPO "$DEPS"
  elif [[ ! "$ACTION" = "bottle" ]]; then
    log "checking for updates to brew"
    git fetch origin > /dev/null
    git reset --hard origin/master > /dev/null
    git clean -f
  fi

  # Reset to a deterministic checkout of brew.
  git reset --hard $BREW_COMMIT

  # Create a local cache directory
  mkdir -p "$DEPS/.cache"

  # Always update the location of the local tap link.
  log "refreshing local tap: osquery-local"
  mkdir -p "$DEPS/Library/Taps/osquery/"

  FORMULA_TAP="$DEPS/Library/Taps/osquery/homebrew-osquery-local"
  if [[ -L "$FORMULA_TAP" ]]; then
    rm -f "$FORMULA_TAP"
  fi
  ln -sf "$FORMULA_DIR" "$FORMULA_TAP"

  export HOMEBREW_NO_ANALYTICS_THIS_RUN=1
  export HOMEBREW_NO_AUTO_UPDATE=1
  export HOMEBREW_CACHE="$DEPS/.cache/"
  export HOMEBREW_MAKE_JOBS=$THREADS
  export HOMEBREW_NO_EMOJI=1
  export HOMEBREW_BOTTLE_ARCH=core2
  export BREW="$DEPS/bin/brew"
  TAPS="$DEPS/Library/Taps/"

  # Grab full clone to perform a pin
  if [[ ! "$ACTION" = "bottle" ]]; then
    log "installing and updating Homebrew core"
    $BREW tap homebrew/core --full
    (cd $TAPS/homebrew/homebrew-core && git pull > /dev/null && \
        git reset --hard $CORE_COMMIT)
  fi

  # Create a 'legacy' mirror.
  if [[ -L "$DEPS/legacy" ]]; then
    # Backwards compatibility for legacy environment.
    rm -f "$DEPS/legacy"
    mkdir -p "$DEPS/legacy"
  elif [[ ! -d "$DEPS/legacy" ]]; then
    mkdir -p "$DEPS/legacy/lib"
  fi

  # Fix for python linking.
  mkdir -p "$DEPS/lib/python2.7/site-packages"
}

# json_attributes JSON [ATTRIBUTE_PATH, ...]
#   1: JSON blob
#   N: path(s) to desired attributes
function json_attributes() {
  CMD="import json,sys;obj=json.load(sys.stdin)"

  for attr in ${@:2}; do
    CMD="$CMD;print $attr"
  done

  RESULT=`(echo "${1}" | python -c "${CMD}") 2>/dev/null || echo 'NAN'`
  echo $RESULT
}

function set_deps_compilers() {
  if [[ "$1" = "gcc" ]]; then
    export CC="$DEPS/bin/gcc"
    export CXX="$DEPS/bin/g++"
  elif [[ -f "$DEPS/bin/clang" ]]; then
    export CC="$DEPS/bin/clang"
    export CXX="$DEPS/bin/clang++"
  else
    unset CC
    unset CXX
  fi
}

function brew_clear_cache() {
  if [[ ! -z "$OSQUERY_CLEAR_CACHE" ]]; then
    log "clearing dependency cache"
    rm -rf "$DEPS/.cache/*"
  fi
}

# local_brew_package TYPE NAME [ARGS, ...]
#   1: tool/dependency/link/upstream/upstream-link
#   2: formula name
#   N: arguments to install
function brew_internal() {
  TYPE="$1"
  TOOL="$2"
  shift
  shift

  FORMULA="$TOOL"
  INFO=`$BREW info --json=v1 "${FORMULA}"`
  RESULTS=$(json_attributes "$INFO" 'obj[0]["installed"][0]["version"]' \
                                    'obj[0]["versions"]["stable"]' \
                                    'obj[0]["revision"]' \
                                    'obj[0]["linked_keg"]')
  read -r -a RESULTS <<< "$RESULTS"

  INSTALLED="${RESULTS[0]}"
  STABLE="${RESULTS[1]}"
  REVISION="${RESULTS[2]}"
  LINKED="${RESULTS[3]}"

  if [[ ! "$REVISION" = "0" ]]; then
    STABLE="${STABLE}_${REVISION}"
  fi

  # Add build arguments depending on requested from-source or default build.
  ARGS="$@"

  if [[ "$TYPE" = "uninstall" ]]; then
    if [[ ! "$INSTALLED" = "NAN" ]]; then
      log "brew package $TOOL uninstalling version: ${STABLE}"
      $BREW uninstall --force "${FORMULA}"
    fi
    return
  fi

  # Configure additional arguments if installing from a local formula.
  POSTINSTALL=0
  ARGS="$ARGS --ignore-dependencies --env=std"
  if [[ "$FORMULA" == *"osquery"* ]]; then
    if [[ -z "$OSQUERY_BUILD_DEPS" ]]; then
      ARGS="$ARGS --force-bottle"
    else
      ARGS="$ARGS --build-bottle"
      POSTINSTALL=1
    fi
    if [[ "$TYPE" = "dependency" ]]; then
      ARGS="$ARGS --cc=clang"
    fi
    if [[ ! -z "$DEBUG" ]]; then
      ARGS="$ARGS -vd"
    fi
    if [[ ! -z "$VERBOSE" ]]; then
      ARGS="$ARGS -v"
    fi
  else
    ARGS="$ARGS --force-bottle"
  fi

  # If linking, only link if not linked and return immediately.
  if [[ "$TYPE" = "link" ]]; then
    if [[ ! "$LINKED" = "$STABLE" ]]; then
      $BREW link --force "${FORMULA}"
    fi
    return
  fi

  if [[ "$TYPE" = "unlink" ]]; then
    if [[ "$LINKED" = "$STABLE" ]]; then
      $BREW unlink --force "${FORMULA}"
    fi
    return
  fi

  export HOMEBREW_OPTIMIZATION_LEVEL=-Os
  if [[ ! -z "$OSQUERY_BUILD_BOTTLES" && "$FORMULA" == *"osquery"* ]]; then
    $BREW bottle --skip-relocation "${FORMULA}"
  elif [[ "$TYPE" = "clean" ]]; then
    if [[ "${STABLE}" = "NAN_NAN" ]]; then
      log "brew cleaning older or forward-dependent version of $TOOL: ${INSTALLED}"
      $BREW uninstall --ignore-dependencies "${FORMULA}"
    elif [[ ! "${INSTALLED}" = "${STABLE}" && ! "${INSTALLED}" = "NAN" ]]; then
      log "brew cleaning older version of $TOOL: ${INSTALLED}"
      $BREW uninstall --ignore-dependencies "${FORMULA}"
    fi
  elif [[ "${INSTALLED}" = "NAN" || "${INSTALLED}" = "None" ]]; then
    log "brew package $TOOL installing new version: ${STABLE}"
    $BREW install $ARGS "${FORMULA}"
  elif [[ ! "${INSTALLED}" = "${STABLE}" || "${FROM_BOTTLE}" = "true" ]]; then
    log "brew package $TOOL upgrading to new version: ${STABLE}"
    $BREW uninstall --ignore-dependencies "${FORMULA}"
    $BREW install $ARGS "${FORMULA}"
  else
    log "brew package $TOOL is already installed: ${STABLE}"
  fi

  if [[ "$POSTINSTALL" = "1" ]]; then
    $BREW postinstall "${FORMULA}"
  fi
}

function brew_tool() {
  brew_internal "tool" $@
}

function brew_dependency() {
  # Essentially uses clang instead of GCC.
  set_deps_compilers clang
  brew_internal "dependency" $@
  if [[ -f "$DEPS/bin/gcc" ]]; then
    set_deps_compilers gcc
  fi
}

function brew_link() {
  brew_internal "link" $@
}

function brew_unlink() {
  brew_internal "unlink" $@
}

function brew_uninstall() {
  brew_internal "uninstall" $@
}

function brew_clean() {
  # Remove older versions if installed.
  brew_internal "clean" $@
}

function brew_bottle() {
  FORMULA=$1
  $BREW bottle --skip-relocation "${FORMULA}"

  INFO=`$BREW info --json=v1 "${FORMULA}"`
  INSTALLED=$(json_attributes "${INFO}" 'obj[0]["installed"][0]["version"]')

  ARIN=(${FORMULA//// })
  TOOL=${ARIN[2]}

  FORMULA_FILE=${FORMULA_DIR}/${TOOL}.rb
  if [[ ! -f "$FORMULA_FILE" ]]; then
    log "[!] cannot install bottle hash into $FORMULA_FILE"
    return
  fi

  HASH=$(shasum -a 256 $DEPS_DIR/${TOOL}-${INSTALLED}* | awk '{print $1}')

  log "installing $HASH into $FORMULA_FILE"
  if [[ "$BREW_TYPE" = "linux" ]]; then
    SED="sed -i "
    SUFFIX=$LINUX_BOTTLE_SUFFIX
  else
    SED="sed -i .orig "
    SUFFIX=$DARWIN_BOTTLE_SUFFIX
  fi

  $SED "s/sha256 \"\\(.*\\)\" => :${SUFFIX}/sha256 \"${HASH}\" => :${SUFFIX}/g" $FORMULA_FILE
  cp $DEPS_DIR/${TOOL}-${INSTALLED}.${SUFFIX}.bottle.tar.gz $CURRENT_DIR
}

function brew_postinstall() {
  TOOL=$1
  if [[ ! -z "$OSQUERY_BUILD_DEPS" ]]; then
    $BREW postinstall "${TOOL}"
  fi
}

function deps_version() {
  DEPS_DIR=$1
  VERSION=$2
  CURRENT="0"
  if [[ -f "$DEPS_DIR/DEPS_VERSION" ]]; then
    CURRENT=$(cat $DEPS_DIR/DEPS_VERSION || echo -n '0')
  fi

  if [[ "$VERSION" != "$CURRENT" && ! "$CURRENT" = "0" ]]; then
    log "dependency version changed removing existing dependencies"
    do_sudo rm -rf "$DEPS_DIR/*"
  fi

  if [[ -d "$DEPS_DIR/Cellar" ]]; then
    INSTALLED_COUNT=$(ls -l $DEPS_DIR/Cellar| grep -v ^l | wc -l)
    if [[ "$CURRENT" = "0" && ! $INSTALLED_COUNT = "0" ]]; then
      log "dependencies are unversioned removing existing dependencies"
      do_sudo rm -rf "$DEPS_DIR/*"
    fi
  fi
}

function package() {
  if [[ $FAMILY = "debian" ]]; then
    INSTALLED=`dpkg-query -W -f='${Status} ${Version}\n' $1 || true`
    if [[ -n "$INSTALLED" && ! "$INSTALLED" = *"unknown ok not-installed"* ]]; then
      log "$1 is already installed. skipping."
    else
      log "installing $1"
      sudo DEBIAN_FRONTEND=noninteractive apt-get install $1 -y -q --no-install-recommends
    fi
  elif [[ $FAMILY = "redhat" ]]; then
    if [[ ! -n "$(rpm -V $1)" ]]; then
      log "$1 is already installed. skipping."
    else
      log "installing $1"
      if [[ $OS = "fedora" ]]; then
        sudo dnf install $1 -y
      else
        sudo yum install $1 -y
      fi
    fi
  elif [[ $OS = "darwin" ]]; then
    if [[ -n "$(brew list | grep $1)" ]]; then
      log "$1 is already installed. skipping."
    else
      log "installing $1"
      unset LIBNAME
      unset HOMEBREW_BUILD_FROM_SOURCE
      export HOMEBREW_MAKE_JOBS=$THREADS
      export HOMEBREW_NO_EMOJI=1
      HOMEBREW_ARGS=""
      if [[ $1 = "rocksdb" ]]; then
        # Build RocksDB from source in brew
        export LIBNAME=librocksdb_lite
        export HOMEBREW_BUILD_FROM_SOURCE=1
        HOMEBREW_ARGS="--build-bottle --with-lite"
      elif [[ $1 = "gflags" ]]; then
        HOMEBREW_ARGS="--build-bottle --with-static"
      elif [[ $1 = "libressl" ]]; then
        HOMEBREW_ARGS="--build-bottle"
      elif [[ $1 = "aws-sdk-cpp" ]]; then
        HOMEBREW_ARGS="--build-bottle --with-static --without-http-client"
      fi
      if [[ "$2" = "devel" ]]; then
        HOMEBREW_ARGS="${HOMEBREW_ARGS} --devel"
      fi
      brew install -v $HOMEBREW_ARGS $1 || brew upgrade -v $HOMEBREW_ARGS $1
    fi
  elif [[ $OS = "freebsd" ]]; then
    if pkg info -q $1; then
      log "$1 is already installed. skipping."
    else
      log "installing $1"
      sudo pkg install -y $1
    fi
  elif [ $OS = "arch" ] || [ $OS="manjaro" ]; then
    if pacman -Qq $1 >/dev/null; then
      log "$1 is already installed. skipping."
    else
      log "installing $1"
      sudo pacman -S --noconfirm $1
    fi
  fi
}

function ports() {
  PKG="$1"
  log "building port $1"
  (cd /usr/ports/$1; do_sudo make deinstall)
  (cd /usr/ports/$1; do_sudo make install clean BATCH=yes)
}

function check() {
  CMD="$1"
  DISTRO_BUILD_DIR="$2"
  platform OS

  if [[ $OS = "darwin" ]]; then
    HASH=`shasum "$0" | awk '{print $1}'`
  elif [[ $OS = "freebsd" ]]; then
    HASH=`sha1 -q "$0"`
  else
    HASH=`sha1sum "$0" | awk '{print $1}'`
  fi

  if [[ "$CMD" = "build" ]]; then
    echo $HASH > "build/$DISTRO_BUILD_DIR/.provision"
    if [[ ! -z "$SUDO_USER" ]]; then
      chown $SUDO_USER "build/$DISTRO_BUILD_DIR/.provision" > /dev/null 2>&1 || true
    fi
    return
  elif [[ ! "$CMD" = "check" ]]; then
    return
  fi

  if [[ "$#" < 2 ]]; then
    echo "Usage: $0 (check|build) BUILD_PATH"
    exit 1
  fi

  CHECKPOINT=`cat $DISTRO_BUILD_DIR/.provision 2>&1 &`
  if [[ ! $HASH = $CHECKPOINT ]]; then
    echo "Requested dependencies may have changed, run: make deps"
    exit 1
  fi
  exit 0
}
