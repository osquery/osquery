#!/usr/bin/env bash

#
# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
#

# Refresh tools/deployment/certs.pem from the Mozilla CA bundle published by
# the curl project, and write a markdown summary of what changed.
#
# Usage: update_ca_bundle.sh <path/to/certs.pem> <path/to/summary.md>
#
# Exits 0 whether or not the bundle changed. The summary is only written when
# it did.

set -euo pipefail

# sort and comm must agree on collation
export LC_ALL=C

readonly BUNDLE_URL="https://curl.se/ca/cacert.pem"
readonly CHECKSUM_URL="https://curl.se/ca/cacert.pem.sha256"

# Mozilla's store is ~150 roots; anything far below that is a broken download.
readonly MIN_CERT_COUNT=100

main() {
  if [[ $# != 2 ]] ; then
    printf "Usage:\n\t%s <path/to/certs.pem> <path/to/summary.md>\n\n" "${0}"
    return 1
  fi

  local target="${1}"
  local summary="${2}"

  local work_dir
  work_dir="$(mktemp -d "${TMPDIR:-/tmp}/ca_bundle.XXXXXX")"
  # work_dir is local, so expand it now rather than when the trap fires
  # shellcheck disable=SC2064
  trap "rm -rf '${work_dir}'" EXIT

  local new_bundle="${work_dir}/cacert.pem"

  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --retry 3 --output "${new_bundle}" "${BUNDLE_URL}"

  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --retry 3 --output "${work_dir}/cacert.pem.sha256" "${CHECKSUM_URL}"

  local expected_hash actual_hash
  expected_hash="$(awk '{ print $1 }' "${work_dir}/cacert.pem.sha256")"
  actual_hash="$(shasum -a 256 "${new_bundle}" | awk '{ print $1 }')"

  if [[ "${expected_hash}" != "${actual_hash}" ]] ; then
    echo "Checksum mismatch: expected ${expected_hash}, got ${actual_hash}"
    return 1
  fi

  if ! grep -q "^## Bundle of CA Root Certificates" "${new_bundle}" ; then
    echo "The downloaded file does not look like a Mozilla CA bundle"
    return 1
  fi

  # Make sure every certificate in the bundle parses
  list_subjects "${new_bundle}" > "${work_dir}/new_subjects.txt"

  local new_count
  new_count="$(wc -l < "${work_dir}/new_subjects.txt" | tr -d ' ')"

  local begin_count
  begin_count="$(grep -c "^-----BEGIN CERTIFICATE-----" "${new_bundle}")"

  if [[ "${new_count}" != "${begin_count}" ]] ; then
    echo "Parsed ${new_count} certificates but found ${begin_count} PEM blocks"
    return 1
  fi

  if (( new_count < MIN_CERT_COUNT )) ; then
    echo "The downloaded bundle only contains ${new_count} certificates"
    return 1
  fi

  if cmp -s "${new_bundle}" "${target}" ; then
    echo "The CA bundle is already up to date"
    return 0
  fi

  list_subjects "${target}" > "${work_dir}/old_subjects.txt"

  local old_count
  old_count="$(wc -l < "${work_dir}/old_subjects.txt" | tr -d ' ')"

  local old_date new_date
  old_date="$(bundle_date "${target}")"
  new_date="$(bundle_date "${new_bundle}")"

  {
    echo "This updates \`tools/deployment/certs.pem\` from ${BUNDLE_URL}."
    echo
    echo "| | Mozilla data as of | Certificates |"
    echo "|---|---|---|"
    echo "| Current | ${old_date} | ${old_count} |"
    echo "| New | ${new_date} | ${new_count} |"
    echo
    echo "SHA256: \`${actual_hash}\` (matches ${CHECKSUM_URL})"
    echo

    echo "<details><summary>Added certificates</summary>"
    echo
    echo '```'
    comm -13 "${work_dir}/old_subjects.txt" "${work_dir}/new_subjects.txt"
    echo '```'
    echo "</details>"
    echo

    echo "<details><summary>Removed certificates</summary>"
    echo
    echo '```'
    comm -23 "${work_dir}/old_subjects.txt" "${work_dir}/new_subjects.txt"
    echo '```'
    echo "</details>"
  } > "${summary}"

  cp "${new_bundle}" "${target}"

  echo "Updated ${target}: ${old_count} -> ${new_count} certificates"
  return 0
}

# Print one sorted subject line per certificate. Fails if any certificate does
# not parse.
list_subjects() {
  openssl crl2pkcs7 -nocrl -certfile "${1}" \
    | openssl pkcs7 -print_certs -noout \
    | sed -n 's/^subject=[ ]*//p' \
    | sort
}

bundle_date() {
  sed -n 's/^## Certificate data from Mozilla as of: //p' "${1}" | head -n 1
}

main "$@"
