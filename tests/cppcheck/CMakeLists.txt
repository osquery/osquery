# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

include(ProcessorCount)

function(cppcheckMain)
  find_package(cppcheck)
  if(NOT CPPCHECK_FOUND)
    message(STATUS "cppcheck: The executable was not found")
    return()
  endif()

  if(NOT CMAKE_EXPORT_COMPILE_COMMANDS)
    message(STATUS "cppcheck: CMAKE_EXPORT_COMPILE_COMMANDS must be enabled")
    return()
  endif()

  message(STATUS "cppcheck: Enabled with ${CPPCHECK_EXECUTABLE}")

  ProcessorCount(job_count)
  math(EXPR job_count "${job_count} + 1")
  set(multithread_options
    -j ${job_count}
  )

  file(READ "${CMAKE_CURRENT_SOURCE_DIR}/suppressions_list.txt"
    cppcheck_suppressions_list
  )

  string(REPLACE "\n" ", " cppcheck_suppressions_list "${cppcheck_suppressions_list}")

  # These folders will not be analyzed, greatly increasing the analysis speed;
  # this only works for source files, while included headers will still cause warnings,
  # which will be covered by the suppression list.
  set(ignored_folders
    -i "*/libraries/*"
    -i "*/libs/src/*"
    -i "*/installed_formulas/*"
    -i "*/openssl/*"
  )

  # We don't care if multithreading disables the unusedFunction check, since that would turn off
  # suppressions (and we don't want to waste time analyzing the source modules)
  add_custom_target(
    cppcheck
    COMMAND "${CMAKE_COMMAND}" -E echo "Suppression list: '${cppcheck_suppressions_list}'"
    COMMAND cppcheck::cppcheck "--suppressions-list=${CMAKE_CURRENT_SOURCE_DIR}/suppressions_list.txt"
            "--library=${CMAKE_CURRENT_SOURCE_DIR}/libraries/googletest.cfg" ${multithread_options}
            --enable=all --platform=unix64 --std=c++17 "--project=${CMAKE_BINARY_DIR}/compile_commands.json"
            ${ignored_folders} -q
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Running Cppcheck ${CPPCHECK_VERSION_STRING}"
    VERBATIM
  )
endfunction()

cppcheckMain()
