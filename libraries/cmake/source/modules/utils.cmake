# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

cmake_minimum_required(VERSION 3.13.3)

option(OSQUERY_THIRD_PARTY_SOURCE_MODULE_WARNINGS "This option can be enable to show all warnings in the source modules. Not recommended" OFF)

function(getGitExecutableName output_variable)
  set(output "git")
  if(DEFINED PLATFORM_WINDOWS)
    set(output "${output}.exe")
  endif()

  set("${output_variable}" "${output}" PARENT_SCOPE)
endfunction()

function(locateGitExecutable output_variable)
  getGitExecutableName(git_executable_name)

  find_program(git_path "${git_executable_name}")
  if("${git_path}" STREQUAL "git_path-NOTFOUND")
    set("${output_variable}" "git_path-NOTFOUND" PARENT_SCOPE)

  else()
    set("${output_variable}" "${git_path}" PARENT_SCOPE)
  endif()
endfunction()

function(initializeGitSubmodule submodule_path)
  file(GLOB submodule_folder_contents "${submodule_path}/*")

  list(LENGTH submodule_folder_contents submodule_folder_file_count)
  if(NOT ${submodule_folder_file_count} EQUAL 0)
    return()
  endif()

  locateGitExecutable(git_executable_path)
  if("${git_executable_path}" STREQUAL "git_executable_path-NOTFOUND")
    message(FATAL_ERROR "Failed to locate the git executable")
  endif()

  execute_process(
    COMMAND "${git_executable_path}" submodule update --init --recursive "${submodule_path}"
    RESULT_VARIABLE process_exit_code
  )

  if(NOT ${process_exit_code} EQUAL 0)
    message(FATAL_ERROR "Failed to update the following git submodule: \"${submodule_path}\"")
  endif()
endfunction()

function(importSourceSubmodule library_name)
  message(STATUS "Importing: source/${library_name}")

  set(directory_path "${CMAKE_SOURCE_DIR}/libraries/cmake/source/${library_name}")
  set(submodule_path "${directory_path}/src")
  initializeGitSubmodule("${submodule_path}")

  if(NOT TARGET thirdparty_source_module_warnings)
    add_library(thirdparty_source_module_warnings INTERFACE)

    if(NOT OSQUERY_THIRD_PARTY_SOURCE_MODULE_WARNINGS)
      target_compile_options(thirdparty_source_module_warnings INTERFACE
        -Wno-everything -Wno-all -Wno-error
      )
    endif()
  endif()

  add_subdirectory("${directory_path}")
endfunction()
