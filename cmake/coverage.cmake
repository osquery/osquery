#
# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
#

function(get_all_targets var)
  set(targets)
  get_all_targets_recursive(targets ${CMAKE_CURRENT_SOURCE_DIR})
  set(${var} ${targets} PARENT_SCOPE)
endfunction()

macro(get_all_targets_recursive targets dir)
  get_property(subdirectories DIRECTORY ${dir} PROPERTY SUBDIRECTORIES)

  foreach(subdir ${subdirectories})
    get_all_targets_recursive(${targets} ${subdir})
  endforeach()

  get_property(current_targets DIRECTORY ${dir} PROPERTY BUILDSYSTEM_TARGETS)
  list(APPEND ${targets} ${current_targets})
endmacro()

# If the script is called as a script, change behavior
if(CMAKE_SCRIPT_MODE_FILE)
  message(STATUS "Searching for profraws in ${COVERAGE_DIR}")
  file(GLOB_RECURSE profraw_files "${COVERAGE_DIR}/*.profraw")
  list(LENGTH profraw_files profraw_files_length)

  if(${profraw_files_length} EQUAL 0)
    message(FATAL_ERROR "No profraw files found!")
  endif()

  message(STATUS "Found ${profraw_files_length} profraw files")

  # Merge all profraws into a single profdata
  execute_process(
    COMMAND "${LLVM_PROFDATA}"
    merge -sparse ${profraw_files}
    -o "${COVERAGE_DIR}/osquery.profdata"
    COMMAND_ERROR_IS_FATAL ANY
  )

  # Check if we have been passed a list of test executables
  list(LENGTH ALL_TESTS ALL_TESTS_LENGTH)

  if(${ALL_TESTS_LENGTH} EQUAL 0)
    message(FATAL_ERROR "No tests to extract coverage for")
  endif()

  # If so, extract/export lcov formatted information for each one of them
  foreach(test ${ALL_TESTS})
    if(NOT EXISTS "${test}")
      message(FATAL_ERROR "Could not find test executable ${test}")
    endif()

    get_filename_component(test_executable_name ${test} NAME)

    # Export the data, ignoring tests source files from the total
    execute_process(
      COMMAND "${LLVM_COV}"
      export "${test}"
      -instr-profile=${COVERAGE_DIR}/osquery.profdata
      --format=lcov
      "--ignore-filename-regex=.*/tests/.*"
      OUTPUT_FILE "${COVERAGE_DIR}/${test_executable_name}.lcov"
      COMMAND_ERROR_IS_FATAL ANY
    )
  endforeach()

  # Merge all lcov files into a single one
  file(GLOB lcov_files "${COVERAGE_DIR}/*.lcov")

  list(LENGTH lcov_files lcov_files_length)

  if(${lcov_files_length} EQUAL 0)
    message(FATAL_ERROR "No lcov files found")
  endif()

  list(TRANSFORM lcov_files PREPEND "-a;")

  execute_process(
    COMMAND "${LCOV}"
    ${lcov_files}
    -o "${COVERAGE_DIR}/osquery.info"
    COMMAND_ERROR_IS_FATAL ANY
  )

  execute_process(
    COMMAND "${GENHTML}"
    "${COVERAGE_DIR}/osquery.info"
    --output-directory "${COVERAGE_DIR}/html-out"
    COMMAND_ERROR_IS_FATAL ANY
  )

else()
  if(OSQUERY_TOOLCHAIN_SYSROOT)
    find_program(llvm_cov llvm-cov HINTS ${OSQUERY_TOOLCHAIN_SYSROOT}/usr/bin
      REQUIRED
      NO_DEFAULT_PATH
      NO_CMAKE_PATH
      NO_CMAKE_ENVIRONMENT_PATH
      NO_SYSTEM_ENVIRONMENT_PATH
      NO_CMAKE_SYSTEM_PATH
      NO_CMAKE_FIND_ROOT_PATH)

    find_program(llvm_profdata llvm-profdata HINTS ${OSQUERY_TOOLCHAIN_SYSROOT}/usr/bin
      REQUIRED
      NO_DEFAULT_PATH
      NO_CMAKE_PATH
      NO_CMAKE_ENVIRONMENT_PATH
      NO_SYSTEM_ENVIRONMENT_PATH
      NO_CMAKE_SYSTEM_PATH
      NO_CMAKE_FIND_ROOT_PATH)
  else()
    find_program(llvm_cov llvm-cov REQUIRED)
    find_program(llvm_profdata llvm-profdata REQUIRED)
  endif()

  find_program(lcov lcov REQUIRED)
  find_program(genhtml genhtml REQUIRED)

  message(STATUS "Found llvm-profdata: ${llvm_profdata}")
  message(STATUS "Found llvm-cov: ${llvm_cov}")
  message(STATUS "Found lcov: ${lcov}")
  message(STATUS "Found genhtml: ${genhtml}")

  file(MAKE_DIRECTORY "${COVERAGE_DIR}")

  # List all targets to then select which ones are tests
  get_all_targets(all_targets)

  list(LENGTH all_targets all_targets_length)

  if(${all_targets_length} EQUAL 0)
    message(FATAL_ERROR "No target found for coverage")
  endif()

  # Then list the full path to the executables to those tests
  foreach(target ${all_targets})
    if("${target}" MATCHES ".*-test$")
      get_target_property(target_dir "${target}" BINARY_DIR)

      # If a test has a custom name, OUTPUT_NAME is set
      get_target_property(target_output_name "${target}" OUTPUT_NAME)

      # Otherwise use the default name
      if("${target_output_name}" STREQUAL "target_output_name-NOTFOUND")
        get_target_property(target_output_name "${target}" NAME)
      endif()

      set(full_executable_path "${target_dir}/${target_output_name}")

      list(APPEND all_tests "${full_executable_path}")
    endif()
  endforeach()

  # osqueryd is added because the python tests use osqueryd to run the tests
  list(APPEND all_tests "${CMAKE_BINARY_DIR}/osquery/osqueryd")

  list(LENGTH all_tests all_tests_length)

  if(${all_tests_length} EQUAL 0)
    message(FATAL_ERROR "No tests found for coverage")
  endif()

  add_custom_target(generate_coverage DEPENDS "${COVERAGE_DIR}/html-out")
  add_custom_command(OUTPUT "${COVERAGE_DIR}/html-out"
    COMMAND ${CMAKE_COMMAND}
    -DCOVERAGE_DIR=${COVERAGE_DIR}
    -DLLVM_COV=${llvm_cov}
    -DLLVM_PROFDATA=${llvm_profdata}
    -DLCOV=${lcov}
    -DGENHTML=${genhtml}
    "-DALL_TESTS=\"${all_tests}\""
    -P ${CMAKE_CURRENT_LIST_FILE}
  )
endif()
