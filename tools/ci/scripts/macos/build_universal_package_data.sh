#!/usr/bin/env bash

set -x

main() {
  extract_package_data "x86_64" || return 1
  extract_package_data "arm64" || return 1
  create_universal_package_data || return 1

  return 0
}

extract_package_data() {
  local architecture="$1"

  if [[ -d "${architecture}" ]] ; then
    rm -rf "${architecture}" || return 1
  fi

  mkdir "${architecture}" || return 1

  if [[ -f "package_data.tar.gz" ]] ; then
    rm -f "package_data.tar.gz" || return 1
  fi

  tar xzf "macos_unsigned_release_package_data_${architecture}/package_data.tar.gz" -C "${architecture}" || return 1
  rm -rf "macos_unsigned_release_package_data_${architecture}" || return 1

  return 0
}

create_universal_package_data() {
  declare -a path_list=("opt/osquery/osquery.app/Contents/MacOS/osqueryd" \
                        "opt/osquery/bin/osqueryi" \
                        "opt/osquery/bin/osqueryd")

  if [[ -d "universal" ]] ; then
    rm -rf "universal" || return 1
  fi

  cp -r "x86_64" "universal" || return 1

  for path in "${path_list[@]}" ; do
    rm -rf "universal/${path}" || return 1

    lipo -create "x86_64/${path}" "arm64/${path}" \
         -output "universal/${path}" || return 1
  done

  tar -C "universal" -pcvzf "package_data.tar.gz" ./ || return 1
  return 0
}

main $@
exit $?
