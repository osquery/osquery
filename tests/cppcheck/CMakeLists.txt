# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

cmake_minimum_required(VERSION 3.13.3)

include(ProcessorCount)

function(cppcheckMain)
  if(NOT DEFINED PLATFORM_LINUX)
    message(STATUS "cppcheck: Platform is not supported")
    return()
  endif()

  if(NOT CMAKE_EXPORT_COMPILE_COMMANDS)
    message(STATUS "cppcheck: CMAKE_EXPORT_COMPILE_COMMANDS must be enabled")
    return()
  endif()

  find_program(OSQUERY_CPPCHECK_PATH cppcheck)
  if("${OSQUERY_CPPCHECK_PATH}" STREQUAL "OSQUERY_CPPCHECK_PATH-NOTFOUND")
    message(STATUS "cppcheck: The executable was not found!")
    return()
  endif()

  if(NOT OSQUERY_BUILD_TESTS)
    ProcessorCount(job_count)

    set(multithread_options
      -j ${job_count}
    )

    message(WARNING "cppcheck: OSQUERY_BUILD_TESTS is OFF, disabling 'unusedFunction' checks and enabling multi-thread support")
  endif()

  execute_process(
    COMMAND "${OSQUERY_CPPCHECK_PATH}" "--version"
    OUTPUT_VARIABLE cppcheck_version
  )

  file(READ "${CMAKE_CURRENT_SOURCE_DIR}/suppressions_list.txt"
    cppcheck_suppressions_list
  )

  string(REPLACE "\n" ", " cppcheck_suppressions_list "${cppcheck_suppressions_list}")

  add_custom_target(
    cppcheck
    COMMAND "${CMAKE_COMMAND}" -E echo "Suppression list: '${cppcheck_suppressions_list}'"
    COMMAND "${OSQUERY_CPPCHECK_PATH}" "--suppressions-list=${CMAKE_CURRENT_SOURCE_DIR}/suppressions_list.txt" "--library=${CMAKE_CURRENT_SOURCE_DIR}/libraries/googletest.cfg" ${multithread_options} --enable=all --platform=unix64 "--project=${CMAKE_BINARY_DIR}/compile_commands.json" --quiet
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Running ${cppcheck_version}"
    VERBATIM
  )
endfunction()

cppcheckMain()
