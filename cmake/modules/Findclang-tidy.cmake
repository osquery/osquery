# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(findClangTidy)
  # Look for the clang-tidy executable
  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    set(executable_name "clang-tidy")

    set(optional_path_suffix_list
      PATH_SUFFIXES bin usr/bin
    )

    if(NOT "${OSQUERY_TOOLCHAIN_SYSROOT}" STREQUAL "")
      set(optional_path_list
        PATHS "${OSQUERY_TOOLCHAIN_SYSROOT}"
      )
    endif()

  else()
    set(executable_name "clang-tidy.exe")
  endif()

  find_program("CLANG-TIDY_EXECUTABLE"
    NAMES "${executable_name}"
    DOC "clang-tidy executable path"

    ${optional_path_list}
    ${optional_path_suffix_list}
  )

  if("${CLANG-TIDY_EXECUTABLE}" STREQUAL "CLANG-TIDY_EXECUTABLE-NOTFOUND")
    return()
  endif()

  # Get the version string
  execute_process(
    COMMAND "${CLANG-TIDY_EXECUTABLE}" --version
    OUTPUT_VARIABLE version_output
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  string(REPLACE "\n" "" version_output "${version_output}")
  string(REPLACE " " ";" version_output_as_list "${version_output}")

  list(GET version_output_as_list 5 clang_tidy_version)
  set(CLANG-TIDY_VERSION_STRING "${clang_tidy_version}" PARENT_SCOPE)

  # Create an imported target
  add_executable(clang-tidy::clang-tidy IMPORTED)

  set_target_properties(
    clang-tidy::clang-tidy PROPERTIES
    IMPORTED_LOCATION "${CLANG-TIDY_EXECUTABLE}"
  )
endfunction()

findClangTidy("CLANG-TIDY_EXECUTABLE")
mark_as_advanced("CLANG-TIDY_EXECUTABLE")

find_package(PackageHandleStandardArgs REQUIRED)
find_package_handle_standard_args(clang-tidy
  REQUIRED_VARS "CLANG-TIDY_EXECUTABLE"
  VERSION_VAR "CLANG-TIDY_VERSION_STRING"
)
