#!/usr/bin/env bash

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

# Installs the prerequisites for building osquery on Linux: the distribution
# packages, the osquery toolchain, and a Perl with the modules that the
# OpenSSL build needs. Only the distribution's own default repositories are
# used (no EPEL or other third-party repositories).
#
# Usage: tools/bootstrap-linux.sh [--with-tests] [--venv-dir <dir>]
#                                 [--toolchain-prefix <dir>]

set -euo pipefail

readonly TOOLCHAIN_VERSION="1.2.0"
readonly TOOLCHAIN_SHA256_X86_64="5f9755ea9c7306ada1710674b6e61202252883e01f7adc45a2dc602555c05a87"
readonly TOOLCHAIN_SHA256_AARCH64="82f7f00b0a565416ee2213419c5697108af6694a732971a4231c2491f4270269"
readonly MINIMUM_CMAKE_VERSION="3.21.4"

# Perl modules used by OpenSSL's Configure script. Some distributions (Fedora,
# RHEL) split these into separate packages that a minimal Perl doesn't include.
readonly PERL_MODULES=(FindBin IPC::Cmd File::Copy File::Path File::Glob
  File::Spec::Functions Getopt::Std Scalar::Util)

readonly SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

with_tests=false
venv_dir="${HOME}/.venvs/osquery"
toolchain_prefix="/usr/local"

usage() {
  cat <<EOF
Usage: $0 [--with-tests] [--venv-dir <dir>] [--toolchain-prefix <dir>]

  --with-tests              Also install the Python test prerequisites into a
                            virtualenv
  --venv-dir <dir>          Where to create the test virtualenv
                            (default: ~/.venvs/osquery). Don't share one
                            between machines, e.g. in a source tree shared
                            with a VM host.
  --toolchain-prefix <dir>  Where to install the osquery toolchain
                            (default: /usr/local)
EOF
}

log() {
  echo "==> $*"
}

fail() {
  echo "error: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-tests) with_tests=true ;;
    --venv-dir)
      [[ $# -ge 2 ]] || fail "--venv-dir requires a directory"
      venv_dir="$2"
      shift
      ;;
    --toolchain-prefix)
      [[ $# -ge 2 ]] || fail "--toolchain-prefix requires a directory"
      toolchain_prefix="$2"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
  shift
done

[[ "$(uname -s)" == "Linux" ]] || fail "this script only supports Linux"

if [[ "${EUID}" -eq 0 ]]; then
  sudo=()
else
  command -v sudo >/dev/null || fail "sudo is required when not running as root"
  sudo=(sudo)
  log "Requesting sudo access to install packages"
  sudo -v
fi

# Detect the package manager from /etc/os-release.
[[ -r /etc/os-release ]] || fail "cannot read /etc/os-release"
# shellcheck disable=SC1091
. /etc/os-release
distro_ids=" ${ID:-} ${ID_LIKE:-} "

common_packages=(git python3 bison flex make cmake perl curl tar)

case "${distro_ids}" in
  *" debian "* | *" ubuntu "*)
    package_manager="apt"
    packages=("${common_packages[@]}" ca-certificates xz-utils)
    test_packages=(python3-venv)
    ;;
  *" fedora "* | *" rhel "* | *" centos "*)
    package_manager="dnf"
    packages=("${common_packages[@]}" ca-certificates xz)
    test_packages=()
    ;;
  *)
    fail "unsupported distribution '${ID:-unknown}'. Install the equivalent" \
      "of these packages with your package manager: ${common_packages[*]}" \
      "xz ccache (optional), then follow the manual steps in" \
      "docs/wiki/development/building.md"
    ;;
esac

if [[ "${with_tests}" == true ]]; then
  packages+=("${test_packages[@]}")
fi

log "Installing packages with ${package_manager}: ${packages[*]}"
case "${package_manager}" in
  apt)
    "${sudo[@]}" apt-get update
    "${sudo[@]}" apt-get install -y --no-install-recommends "${packages[@]}"
    if "${sudo[@]}" apt-get install -y --no-install-recommends ccache; then
      log "Installed ccache"
    else
      log "ccache is not available; continuing without it"
    fi
    ;;
  dnf)
    "${sudo[@]}" dnf install -y "${packages[@]}"
    # ccache is optional, and on RHEL-compatible distributions it is only in
    # EPEL, which this script does not enable.
    if dnf -q info ccache >/dev/null 2>&1; then
      "${sudo[@]}" dnf install -y ccache
    else
      log "ccache is not in the enabled repositories; continuing without it"
    fi
    ;;
esac

# Check CMake's version; some LTS distributions ship one that is too old.
cmake_version="$(cmake --version | head -n1 | awk '{print $3}')"
if [[ "$(printf '%s\n%s\n' "${MINIMUM_CMAKE_VERSION}" "${cmake_version}" |
  sort -V | head -n1)" != "${MINIMUM_CMAKE_VERSION}" ]]; then
  fail "CMake ${cmake_version} is too old; osquery needs" \
    "${MINIMUM_CMAKE_VERSION} or newer. Install a newer one from" \
    "https://cmake.org/download/ and put it first on your PATH."
fi
log "Found CMake ${cmake_version}"

# Check that the perl first on PATH, which the OpenSSL build uses, has the
# modules it needs.
missing_modules=()
for module in "${PERL_MODULES[@]}"; do
  if ! perl -M"${module}" -e1 >/dev/null 2>&1; then
    missing_modules+=("${module}")
  fi
done
if [[ ${#missing_modules[@]} -gt 0 ]]; then
  fail "$(command -v perl) is missing Perl modules needed to build OpenSSL:" \
    "${missing_modules[*]}. If this is not your distribution's Perl, put" \
    "/usr/bin first on your PATH."
fi
log "Found $(command -v perl) with the required modules"

# Install the osquery toolchain.
case "$(uname -m)" in
  x86_64) toolchain_sha256="${TOOLCHAIN_SHA256_X86_64}" ;;
  aarch64) toolchain_sha256="${TOOLCHAIN_SHA256_AARCH64}" ;;
  *) fail "the osquery toolchain is not available for $(uname -m)" ;;
esac

toolchain_dir="${toolchain_prefix}/osquery-toolchain"
if [[ -x "${toolchain_dir}/usr/bin/clang" ]]; then
  log "osquery toolchain already installed at ${toolchain_dir}"
else
  toolchain_archive="osquery-toolchain-${TOOLCHAIN_VERSION}-$(uname -m).tar.xz"
  toolchain_url="https://github.com/osquery/osquery-toolchain/releases/download/${TOOLCHAIN_VERSION}/${toolchain_archive}"
  download_dir="$(mktemp -d)"
  trap 'rm -rf "${download_dir}"' EXIT

  log "Downloading ${toolchain_url}"
  curl -fL --retry 3 -o "${download_dir}/${toolchain_archive}" "${toolchain_url}"

  log "Verifying the toolchain checksum"
  echo "${toolchain_sha256}  ${download_dir}/${toolchain_archive}" |
    sha256sum --check --quiet - ||
    fail "checksum mismatch for ${toolchain_archive}"

  log "Installing the osquery toolchain to ${toolchain_dir}"
  "${sudo[@]}" mkdir -p "${toolchain_prefix}"
  "${sudo[@]}" tar -xJf "${download_dir}/${toolchain_archive}" \
    -C "${toolchain_prefix}"
fi

# Optionally set up the Python test prerequisites in a virtualenv.
if [[ "${with_tests}" == true ]]; then
  log "Installing Python test prerequisites into ${venv_dir}"
  mkdir -p "$(dirname "${venv_dir}")"
  if ! python3 -m venv "${venv_dir}" || [[ ! -x "${venv_dir}/bin/python3" ]]; then
    fail "could not create a virtualenv at ${venv_dir}. If that directory" \
      "holds a virtualenv from another machine (for example, a source tree" \
      "shared with a VM host), use --venv-dir to choose another location."
  fi
  "${venv_dir}/bin/pip" install --upgrade pip
  "${venv_dir}/bin/pip" install -r "${SOURCE_DIR}/tools/tests/requirements.txt"
fi

log "Done. To build osquery:"
if [[ "${toolchain_prefix}" == "/usr/local" ]]; then
  echo "  make build"
  if [[ "${with_tests}" == true ]]; then
    echo "Run the tests with: make test"
  fi
else
  # The Makefile's targets cannot pass a custom toolchain sysroot.
  echo "  cmake --preset linux -DOSQUERY_TOOLCHAIN_SYSROOT=${toolchain_dir}"
  echo "  cmake --build --preset linux -j \$(nproc)"
fi
if [[ "${with_tests}" == true ]]; then
  echo "Activate the test virtualenv with: source ${venv_dir}/bin/activate"
fi
