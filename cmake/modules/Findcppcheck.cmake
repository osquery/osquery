# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(FindCppcheck)
  # Look for the cppcheck executable
  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    set(executable_name "cppcheck")

    set(optional_path_suffix_list
      PATH_SUFFIXES bin usr/bin
    )

    if(NOT "${OSQUERY_TOOLCHAIN_SYSROOT}" STREQUAL "")
      set(optional_path_list
        PATHS "${OSQUERY_TOOLCHAIN_SYSROOT}"
      )
    endif()
  elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
    set(executable_name "cppcheck")
    
    set(optional_path_suffix_list 
      PATH_SUFFIXES usr/local/bin
    )
  else()
    set(executable_name "cppcheck.exe")
  endif()

  find_program("CPPCHECK_EXECUTABLE"
    NAMES "${executable_name}"
    DOC "Cppcheck executable path"

    ${optional_path_list}
    ${optional_path_suffix_list}
  )

  if("${CPPCHECK_EXECUTABLE}" STREQUAL "CPPCHECK_EXECUTABLE-NOTFOUND")
    return()
  endif()

  # Get the version string
  execute_process(
    COMMAND "${CPPCHECK_EXECUTABLE}" --version
    OUTPUT_VARIABLE version_output
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  string(REPLACE "Cppcheck " "" version_output "${version_output}")
  set(CPPCHECK_VERSION_STRING "${version_output}" PARENT_SCOPE)

  # Create an imported target
  add_executable(cppcheck::cppcheck IMPORTED)

  set_target_properties(
    cppcheck::cppcheck PROPERTIES
    IMPORTED_LOCATION "${CPPCHECK_EXECUTABLE}"
  )
endfunction()

FindCppcheck("CPPCHECK_EXECUTABLE")
mark_as_advanced("CPPCHECK_EXECUTABLE")

find_package(PackageHandleStandardArgs REQUIRED)
find_package_handle_standard_args(cppcheck
  REQUIRED_VARS "CPPCHECK_EXECUTABLE"
  VERSION_VAR "CPPCHECK_VERSION_STRING"
)
