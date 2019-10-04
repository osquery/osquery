# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

cmake_minimum_required(VERSION 3.13.3)

include(ProcessorCount)

function(clangTidyMain)
  if(NOT DEFINED PLATFORM_LINUX)
    message(STATUS "clang-tidy: Platform is not supported")
    return()
  endif()

  if(NOT CMAKE_EXPORT_COMPILE_COMMANDS)
    message(STATUS "clang-tidy: CMAKE_EXPORT_COMPILE_COMMANDS must be enabled")
    return()
  endif()

  if("${OSQUERY_CLANG_TIDY_PATH}" STREQUAL "" AND NOT "${OSQUERY_TOOLCHAIN_SYSROOT}" STREQUAL "")
    overwrite_cache_variable(OSQUERY_CLANG_TIDY_PATH STRING
      "${OSQUERY_TOOLCHAIN_SYSROOT}/usr/bin/clang-tidy"
    )
  endif()

  find_program(OSQUERY_CLANG_TIDY_PATH "clang-tidy")
  if("${OSQUERY_CLANG_TIDY_PATH}" STREQUAL "OSQUERY_CLANG_TIDY_PATH-NOTFOUND")
    message(STATUS "clang-tidy: The executable was not found")
    return()

  elseif(NOT EXISTS "${OSQUERY_CLANG_TIDY_PATH}")
    message(STATUS "clang-tidy: The provided clang-tidy path is not valid")
    return()
  endif()

  if("${OSQUERY_RUN_CLANG_TIDY_PATH}" STREQUAL "")
    get_filename_component(bin_folder_path "${OSQUERY_CLANG_TIDY_PATH}" DIRECTORY)
    get_filename_component(usr_folder_path "${bin_folder_path}" DIRECTORY)

    overwrite_cache_variable(OSQUERY_RUN_CLANG_TIDY_PATH STRING
      "${usr_folder_path}/share/clang/run-clang-tidy.py"
    )
  endif()

  if(NOT EXISTS "${OSQUERY_RUN_CLANG_TIDY_PATH}")
    message(STATUS "clang-tidy: The run-clang-tidy.py script is missing from the system!")
    return()
  endif()

  ProcessorCount(job_count)
  math(EXPR job_count "${job_count} + 1")

  add_custom_target(
    clang-tidy
    COMMAND "${OSQUERY_RUN_CLANG_TIDY_PATH}" "-p" "${CMAKE_BINARY_DIR}" "-j" "${job_count}" "-clang-tidy-binary" "${OSQUERY_CLANG_TIDY_PATH}"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Running clang-tidy with ${job_count} jobs"
    VERBATIM
  )
endfunction()

clangTidyMain()
