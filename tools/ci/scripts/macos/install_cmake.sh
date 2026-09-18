#!/usr/bin/env bash

main() {
  if [[ $# != 3 ]] ; then
    printf "Usage:\n\t${0} </path/to/download/folder> </path/to/install/folder> <major.minor.patch>\n\n"
    return 1
  fi

  local download_folder="${1}"
  local install_folder="${2}"
  local long_version="${3}"

  local short_version=$(echo ${long_version} | cut -d '.' -f 1-2)

  local folder_name="cmake-${long_version}-macos-universal"
  local filename="${folder_name}.tar.gz"

  local url="https://cmake.org/files/v${short_version}/${filename}"
  local local_path="${download_folder}/${filename}"

  mkdir -p "${download_folder}" || return 1

  if [[ ! -f "${local_path}" ]]; then
    curl -fL --retry 3 --retry-delay 2 -o "${local_path}" "${url}" || return 1
  fi

  if [[ ! -s "${local_path}" ]]; then
    echo "Download failed: ${local_path} is missing or empty" >&2
    return 1
  fi

  mkdir -p "${install_folder}" || return 1

  tar xf "${local_path}" \
      -C "${install_folder}"

  echo "${install_folder}/${folder_name}/CMake.app/Contents/bin" >> $GITHUB_PATH

  return 0
}

main $@
exit $?
